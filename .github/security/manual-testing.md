# Manual security regression checks

These checks are intended for the local Docker deployment only. Do not send the
test payloads or disposable credentials to production. The workflow runs the
safe, repeatable `curl`-equivalent checks in
`manual_security_regression.py`; the steps below preserve the Burp Suite,
browser DevTools, and Wireshark validation described in the security analysis.

Set the local target to `http://127.0.0.1:8082` unless the approved test
deployment uses another local port.

## SQL injection login regression

Use Burp Repeater, browser DevTools, or this local-only request:

```bash
curl -i -c /tmp/courier-login.cookies \
  -X POST 'http://127.0.0.1:8082/server/api.php?function_code=login' \
  --data-urlencode "email=' OR '1' = '1' -- " \
  --data-urlencode 'password=manual-regression-invalid'
```

The response must not return `admin` or create an authenticated admin session.
Use a disposable test database and do not include real passwords in captured
requests.

## Session reuse and invalidation

1. Create or use a disposable local admin account.
2. Log in, inspect `PHPSESSID` in browser DevTools, and copy it into a separate
   private browser session or Burp Repeater.
3. Request `/Admin/index.php` with the copied cookie.
4. Log out, replay the same cookie, and verify that the admin page is denied.
5. Inspect the cookie attributes. It should include `Secure`, `HttpOnly`, and
   an appropriate `SameSite` value.

The automated workflow runs the logout/replay variant when
`SECURITY_TEST_ADMIN_EMAIL` and `SECURITY_TEST_ADMIN_PASSWORD` repository
secrets are configured. It never prints those values or the session ID.

## Cleartext HTTP validation

In Wireshark, capture only the local test traffic and use a filter such as:

```text
http.request && tcp.port == 8082
```

Follow the login TCP stream and confirm that credentials and `PHPSESSID` are
not readable in cleartext after HTTPS is enabled. The automated check records
an HTTP target as a finding and checks the session cookie's `Secure` flag.
