//! A tuned tunnel's own thread.
//!
//! One packet crosses eight tasks between the wire and a reader: gotatun's
//! socket reader, decrypt, two buffering tasks and its socket writer, the
//! stack pump, and back. On the caller's multi-thread runtime each of those
//! hand-offs can land on a different worker, and an idle worker woken to
//! steal the task finds nothing and parks again. Measured on a loopback bulk
//! download, that wake and park churn is about two worker unparks per
//! packet and most of the tunnel's CPU.
//!
//! A tunnel built with download tuning therefore runs its device and stack
//! pump on one thread of its own, on a current-thread runtime. Its tasks hand
//! packets to each other without waking any other thread; only the caller's
//! readers and writers cross over, once per batch, through the same wakers
//! as before.

use tokio::sync::oneshot;

use crate::error::TunnelError;

/// The thread a tuned tunnel's tasks run on.
///
/// The thread ends, and every task still on it is dropped, when
/// [`TunnelWorker::release`] is called or the worker is dropped.
pub(crate) struct TunnelWorker {
    handle: tokio::runtime::Handle,
    stop: Option<oneshot::Sender<()>>,
}

impl TunnelWorker {
    /// Start the thread and its runtime.
    pub(crate) fn start(proxy_config_id: &str) -> Result<Self, TunnelError> {
        let (stop, stopped) = oneshot::channel::<()>();
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("wireguard-tunnel".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                if ready.send(Ok(runtime.handle().clone())).is_err() {
                    return;
                }
                // Either a release or the worker's drop; both end the thread.
                runtime.block_on(async {
                    let _ = stopped.await;
                });
            })
            .and_then(|_| started.recv().map_err(std::io::Error::other)?)
            .map(|handle| Self {
                handle,
                stop: Some(stop),
            })
            .map_err(|error| {
                TunnelError::Engine(format!(
                    "the tunnel {proxy_config_id} could not start its thread: {error}"
                ))
            })
    }

    /// The runtime the tunnel's tasks are spawned on.
    pub(crate) fn handle(&self) -> &tokio::runtime::Handle {
        &self.handle
    }

    /// The signal that ends the thread, for a teardown that has work of its
    /// own to finish on the thread first: dropping it ends the thread.
    pub(crate) fn release(&mut self) -> Option<oneshot::Sender<()>> {
        self.stop.take()
    }
}

impl Drop for TunnelWorker {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tasks_run_on_the_worker_and_end_with_it() {
        let worker = TunnelWorker::start("worker-test").expect("worker");
        let caller = std::thread::current().id();
        let ran_on = worker
            .handle()
            .spawn(async { std::thread::current().id() })
            .await
            .expect("task");
        assert_ne!(ran_on, caller, "the task ran on the worker's own thread");

        let (_held, parked) = oneshot::channel::<()>();
        let task = worker.handle().spawn(async move {
            let _ = parked.await;
        });
        drop(worker);
        let ended = task.await.expect_err("the worker's end drops its tasks");
        assert!(ended.is_cancelled());
    }

    #[tokio::test]
    async fn a_released_worker_runs_until_the_signal_drops() {
        let mut worker = TunnelWorker::start("worker-test").expect("worker");
        let signal = worker.release().expect("signal");
        let handle = worker.handle().clone();
        drop(worker);
        // The thread outlives the worker while the signal is held.
        let answer = handle.spawn(async { 7 }).await.expect("still running");
        assert_eq!(answer, 7);
        let (_held, parked) = oneshot::channel::<()>();
        let task = handle.spawn(async move {
            let _ = parked.await;
        });
        drop(signal);
        assert!(task.await.expect_err("ended").is_cancelled());
    }
}
