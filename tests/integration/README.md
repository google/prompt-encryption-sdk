# Integration tests

These tests run the real client against a real TLS 1.3 server in the test
process. The server has the real WSGI or ASGI middleware. The tests use only
localhost and temporary files. A fake Google Cloud Attestation (GCA) token
issuer is the only fake. For details, see `tls_testlib.py`.

These tests protect the existing server-only mode from regressions:

-   `server_only_tls_integration_test.py`: attestation, re-attestation, and
    reconnection on the WSGI server and on the ASGI server.
-   `../codelab_api_test.py`: the SDK names that the codelab uses.

## Run the tests

Install the package with the server and test dependencies. Then run pytest from
the root of the repository:

```shell
pip install '.[server,test]'
pytest tests/integration tests/codelab_api_test.py
```

