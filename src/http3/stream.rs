use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, mpsc, oneshot},
    task::AbortHandle,
};

use super::Session;

const WRITE_CHUNK: usize = 64 * 1024;
type ReceiveHalf = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type Reservation = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Command>, mpsc::error::SendError<()>>> + Send>,
>;

enum Command {
    Data(Bytes),
    Flush(oneshot::Sender<()>),
    Finish(oneshot::Sender<()>),
}

struct SenderGuard {
    stream: SendHalf,
    finished: bool,
}

impl Drop for SenderGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.stream
                .stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

/// Reads HTTP/3 DATA directly; only the write side needs a bounded async adapter.
pub(super) struct Http3Stream {
    receive: ReceiveHalf,
    buffered: Bytes,
    trailers: bool,
    eof: bool,
    commands: mpsc::Sender<Command>,
    reservation: Option<Reservation>,
    acknowledgment: Option<oneshot::Receiver<()>>,
    finishing: bool,
    finished: bool,
    writer: AbortHandle,
    session: Arc<Session>,
    _permit: OwnedSemaphorePermit,
}

fn broken() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        "HTTP/3 tunnel stream closed or reset",
    )
}

impl Http3Stream {
    pub(super) fn new(
        mut request: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        session: Arc<Session>,
        permit: OwnedSemaphorePermit,
    ) -> io::Result<Self> {
        // Register under the same lock shutdown drains, so no writer can be
        // spawned after shutdown has collected the owned tasks.
        let mut writers = session.writers.lock().expect("HTTP/3 writers lock");
        if session.stopped.load(Ordering::Acquire) {
            request.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            return Err(broken());
        }
        let (send, receive) = request.split();
        // At most one queued 64 KiB write plus the in-flight write per stream.
        let (commands, mut receiver) = mpsc::channel(1);
        let connection = session.connection.clone();
        let mut sender = SenderGuard {
            stream: send,
            finished: false,
        };
        let task = tokio::spawn(async move {
            let pump = async {
                while let Some(command) = receiver.recv().await {
                    match command {
                        Command::Data(bytes) => sender.stream.send_data(bytes).await?,
                        Command::Flush(ack) => {
                            let _ = ack.send(());
                        }
                        Command::Finish(ack) => {
                            sender.stream.finish().await?;
                            sender.finished = true;
                            let _ = ack.send(());
                            break;
                        }
                    }
                }
                Ok::<_, h3::error::StreamError>(())
            };
            tokio::select! { biased; _ = connection.closed() => {}, _ = pump => {} }
        });
        let writer = task.abort_handle();
        writers.retain(|task| !task.is_finished());
        writers.push(task);
        drop(writers);
        Ok(Self {
            receive,
            buffered: Bytes::new(),
            trailers: false,
            eof: false,
            commands,
            reservation: None,
            acknowledgment: None,
            finishing: false,
            finished: false,
            writer,
            session,
            _permit: permit,
        })
    }

    fn reserve(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<mpsc::OwnedPermit<Command>>> {
        if self.session.stopped.load(Ordering::Acquire) {
            return Poll::Ready(Err(broken()));
        }
        let future = self
            .reservation
            .get_or_insert_with(|| Box::pin(self.commands.clone().reserve_owned()));
        let result = ready!(future.as_mut().poll(cx));
        self.reservation = None;
        Poll::Ready(result.map_err(|_| broken()))
    }

    fn poll_ack(&mut self, cx: &mut Context<'_>, finish: bool) -> Poll<io::Result<()>> {
        if self.session.stopped.load(Ordering::Acquire) {
            return Poll::Ready(Err(broken()));
        }
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        if self.acknowledgment.is_none() {
            let permit = ready!(self.reserve(cx))?;
            let (tx, rx) = oneshot::channel();
            if finish {
                self.finishing = true;
                permit.send(Command::Finish(tx));
            } else {
                permit.send(Command::Flush(tx));
            }
            self.acknowledgment = Some(rx);
        }
        let result =
            ready!(Pin::new(self.acknowledgment.as_mut().expect("acknowledgment")).poll(cx));
        self.acknowledgment = None;
        result.map_err(|_| broken())?;
        if self.finishing {
            self.finished = true;
        }
        if finish && !self.finished {
            // A previously pending flush completed; now enqueue FIN.
            return self.poll_ack(cx, true);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Http3Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.session.stopped.load(Ordering::Acquire) {
            return Poll::Ready(Err(broken()));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if !self.buffered.is_empty() {
                let count = output.remaining().min(self.buffered.len());
                output.put_slice(&self.buffered.split_to(count));
                return Poll::Ready(Ok(()));
            }
            if self.trailers {
                let trailers = ready!(self.receive.poll_recv_trailers(cx)).map_err(|_| broken())?;
                if trailers.is_some() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailers are not permitted in a CONNECT tunnel",
                    )));
                }
                self.eof = true;
                return Poll::Ready(Ok(()));
            }
            match ready!(self.receive.poll_recv_data(cx)).map_err(|_| broken())? {
                Some(mut chunk) => {
                    self.buffered = chunk.copy_to_bytes(chunk.remaining());
                }
                None => {
                    self.trailers = true;
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for Http3Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.finishing || self.finished {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/3 write side is closed",
            )));
        }
        if self.acknowledgment.is_some() {
            ready!(self.poll_ack(cx, false))?;
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let permit = ready!(self.reserve(cx))?;
        let count = bytes.len().min(WRITE_CHUNK);
        permit.send(Command::Data(Bytes::copy_from_slice(&bytes[..count])));
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_ack(cx, false)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_ack(cx, true)
    }
}

impl Drop for Http3Stream {
    fn drop(&mut self) {
        // Quinn's receive-half destructor issues STOP_SENDING even if a read
        // is pending inside the adapter. See PendingRequest's cancellation.
        self.writer.abort();
    }
}
