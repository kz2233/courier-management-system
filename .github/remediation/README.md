# Automated remediation

Run **Actions → Automated security remediation → Run workflow** on the
self-hosted runner. The default source path is the local application checkout:

```text
/home/ubuntu/Desktop/courier-management-system
```

The workflow does not commit or push application changes. It creates a
targeted pre-edit backup and a `remediation.patch` artifact, then builds the
verified image as:

```text
courier-management-system:fixed-<run-id>
```

The remediation pipeline is deliberately isolated from the vulnerable Docker
stack. It uses Semgrep autofix for the login queries and shared session
bootstrap, Rector for session-ID regeneration in successful login branches,
and Ansible to render the local HTTPS redirect, TLS virtual host, HSTS, and
PHP runtime settings.

The verification service uses host ports `18080` and `18443`, a separate
Docker network, and a fresh MariaDB instance. The temporary certificate is
self-signed and is only for localhost testing.

Set the disposable local admin credentials in the repository secrets
`SECURITY_TEST_ADMIN_EMAIL` and `SECURITY_TEST_ADMIN_PASSWORD`. Without them,
logout/session-replay verification is skipped, so the workflow will not claim
weak session management is fixed and the Confluence row remains `VULNERABLE`.
