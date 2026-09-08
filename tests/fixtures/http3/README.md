These are fixed, public TLS test fixtures for loopback HTTP/3 tests.
The server key protects no real service and must never be used in deployment.
The certificate is signed by the fixture CA and covers localhost, 127.0.0.1,
and ::1. Tests explicitly install this CA; the production default does not.
