# Codex Handoff: Courier Management System Security Automation

Last updated: 2026-08-03 (Asia/Kuala_Lumpur)

## Resume Instruction for Codex

Read this file first, then inspect the current repository and machine before making
changes. Paths, installed tools, ports, GitHub secrets, and runner registration are
machine-specific and must be verified on the new device. Do not assume the old
device's `/home/wenhui/...` paths exist.

The immediate goal is to restore and verify the self-hosted GitHub Actions security
pipeline on the new device without losing the existing Semgrep, SonarQube, and OWASP
ZAP automation.

## Project Identity

- GitHub repository: `https://github.com/kz2233/courier-management-system`
- Default branch: `main`
- Workflow: `.github/workflows/build.yml`
- Workflow name: `Build`
- Job name: `Build and analyze`
- Runner type: GitHub Actions self-hosted Linux x64 runner
- Last known runner version: `2.336.0`
- Old runner name: `ubuntu`
- Workflow triggers: push to `main` and manual `workflow_dispatch`

## Completed Progress

- Git remote and `main` branch were connected to the GitHub repository.
- A self-hosted runner was registered and successfully accepted GitHub Actions jobs.
- SonarQube scanning was configured and tested against a local SonarQube server.
- Semgrep scanning was added with bounded execution and a local fallback.
- OWASP ZAP baseline scanning was added against the locally running web application.
- Security reports were uploaded as a GitHub Actions artifact named
  `security-reports`.
- A complete workflow run succeeded after the Semgrep resource limits were added.

Relevant commits:

| Commit | Change |
| --- | --- |
| `6eba19d` | Added Semgrep and OWASP ZAP security scans |
| `7b19120` | Added Semgrep fallback report generation |
| `941ad50` | Hardened the Semgrep fallback |
| `992d62a` | Limited Semgrep fallback resource usage |

Last known successful workflow run:

- Run ID: `30232561973`
- Result: success
- Duration: approximately 3 minutes 57 seconds
- Successful steps: checkout, report directory, Semgrep, SonarQube, ZAP, artifact upload
- ZAP returned warning status/exit code 2, but the step was intentionally nonblocking.
- Semgrep cloud CI did not produce its report in time, so the local rules fallback ran.

## Current Workflow Behavior

The workflow currently performs the following sequence:

1. Checks out the full Git history.
2. Creates `security-reports/`.
3. Runs `semgrep ci` for up to 90 seconds.
4. If needed, runs `semgrep scan --config p/default` with one worker, a 2 GB
   memory limit, and a five-minute timeout.
5. Runs the SonarQube GitHub Action against `http://localhost:9000`.
6. Runs the OWASP ZAP baseline Docker image against `http://127.0.0.1:8082`.
7. Uploads the report directory as the `security-reports` artifact even when a scan
   has warnings or fails.

Semgrep and ZAP currently use `continue-on-error: true`. This means the workflow is
report-oriented and does not fail the build when either scanner reports findings.
SonarQube behavior depends on its action and quality-gate configuration.

## Old Device Configuration

These details describe the previous machine only. Recreate or adapt them on the new
device:

- Old runner directory: `/home/wenhui/Desktop/tools/actions-runner`
- Old runner checkout:
  `/home/wenhui/Desktop/tools/actions-runner/_work/courier-management-system/courier-management-system`
- Hard-coded Semgrep executable:
  `/home/wenhui/.local/bin/semgrep`
- Semgrep version: `1.161.0`
- Web application URL: `http://127.0.0.1:8082`
- SonarQube URL: `http://localhost:9000`
- SonarQube version observed: `26.5.0.122743`
- Docker containers included the web application, databases, SonarQube, and ZAP.
- The web container exposed host port `8082` to container port `80`.

Important: `.github/workflows/build.yml` still contains the old absolute Semgrep
path. Update it for the new device, or preferably make the workflow discover
Semgrep through `PATH`.

## New Device Setup Checklist

- [ ] Clone `https://github.com/kz2233/courier-management-system` and check out `main`.
- [ ] Confirm commit `992d62a` or a newer commit is present.
- [ ] Install Docker and verify the current user can run Docker commands.
- [ ] Start the courier web application and confirm it responds on port `8082`.
- [ ] Start SonarQube and confirm `http://localhost:9000/api/system/status` reports
  `UP`.
- [ ] Create or reuse a SonarQube project and generate a new SonarQube token.
- [ ] Configure the GitHub repository secret `SONAR_TOKEN`.
- [ ] Install Semgrep and authenticate it on the new device if Semgrep App features
  are required.
- [ ] Update the workflow's Semgrep executable path for the new operating-system
  user.
- [ ] Download and configure a new GitHub self-hosted runner for this repository.
- [ ] Install the runner as a service or keep `./run.sh` running while testing.
- [ ] Confirm the runner appears `Online` in GitHub repository settings.
- [ ] Trigger the `Build` workflow manually and watch the self-hosted runner receive
  the job.
- [ ] Download the `security-reports` artifact and verify the Semgrep and ZAP reports
  are nonempty.
- [ ] Decide whether scanner findings should remain nonblocking or fail the build.

## Runner Registration Notes

Runner registration tokens and runner removal tokens are short-lived values obtained
from GitHub repository settings. They are not the same as a personal access token and
must not be stored in this file or committed.

GitHub navigation:

`Repository > Settings > Actions > Runners > New self-hosted runner`

Use the commands GitHub displays for the new device. A runner copied from another
machine should be registered again rather than relying on the old `.runner`
configuration. If an obsolete runner remains listed on GitHub, remove it from the
repository's Runners page.

Typical service commands after registration:

```bash
cd /path/to/actions-runner
sudo ./svc.sh install
sudo ./svc.sh start
sudo ./svc.sh status
```

For an initial foreground test:

```bash
cd /path/to/actions-runner
./run.sh
```

Expected output includes `Connected to GitHub` and `Listening for Jobs`.

## How to Trigger the Pipeline

Either push a commit to `main`, or use GitHub:

`Repository > Actions > Build > Run workflow > main > Run workflow`

The self-hosted runner must be online. SonarQube and the courier application must be
running on the same device because the workflow accesses both through `localhost`.

## Required GitHub and Tool Credentials

- `SONAR_TOKEN`: GitHub Actions repository secret containing a SonarQube user token.
- Semgrep login: local Semgrep authentication if using `semgrep ci` with Semgrep App.
- GitHub runner registration token: generated while registering the runner and not
  saved in the repository.
- Git push authentication: GitHub CLI, SSH key, or a GitHub personal access token.

Never place credential values in this document, the workflow YAML, terminal output
shared publicly, or a Git commit.

## Reports and Evidence

The successful run produced files similar to:

- `security-reports/semgrep-results.json`
- `security-reports/zap-baseline.json`
- `security-reports/zap-baseline.html`
- `security-reports/zap-baseline.md`
- `security-reports/zap.yaml`

Old local assessment notes, if copied from the previous device, were stored outside
the repository at:

- `security-tool-results-summary.md`
- `security-manual-validation-results.md`
- `semgrep-results.json`
- `nuclei-result.txt`
- `zap-reports/`
- `wapiti_report/`

The runner checkout also contained untracked `.scannerwork/` and
`security-reports/` directories. These are generated output, not source files, and
should generally remain uncommitted.

## Confirmed SQL Injection Finding

The login SQL injection was confirmed by manual testing, not clearly discovered by
Semgrep, ZAP, SonarQube, Wapiti, or Nuclei.

Affected endpoint:

```text
POST /server/api.php?function_code=login
```

The earlier validation used an authentication-bypass payload in the email field and
an arbitrary password. The response returned the admin user and a PHP session cookie,
which could then access `/Admin/index.php`. Treat this as a confirmed critical issue.

Do not test this against any system without explicit authorization. On the local lab
application, the next engineering task is to replace string-built SQL with prepared
statements, validate credentials normally, rotate test credentials/sessions, and add
a regression test proving the bypass no longer works.

## Known Problems and Risks

- The old runner service was OOM-killed during an earlier unbounded Semgrep fallback.
  Commit `992d62a` added time and memory limits to prevent recurrence.
- The Semgrep path is hard-coded for the old Linux user.
- The SonarQube URL is hard-coded to localhost even though a `SONAR_HOST_URL` GitHub
  secret previously existed.
- ZAP scans only a baseline unauthenticated view. It may not crawl protected admin
  functionality or detect the confirmed login SQL injection.
- Semgrep and ZAP findings do not currently fail the workflow.
- GitHub actions previously emitted a Node runtime deprecation warning. Check for
  newer major versions of `actions/checkout` and `actions/upload-artifact` before
  upgrading them.
- Generated scan output may contain application URLs, source paths, and security
  details. Review artifacts before sharing them.

## Recommended Next Work

1. Restore the new device's containers, scanner installations, secrets, and runner.
2. Remove machine-specific executable paths from the workflow.
3. Run one manual workflow and verify every report artifact.
4. Fix the confirmed SQL injection and add an automated regression test.
5. Add authenticated ZAP coverage for admin pages if test credentials can be stored
   safely in GitHub Actions secrets.
6. Define enforcement thresholds so high-confidence critical findings fail the build
   while informational ZAP warnings remain visible but nonblocking.

## First Commands for Codex on the New Device

Run read-only checks first and adapt the paths to the new clone:

```bash
git remote -v
git status --short
git log -5 --oneline
sed -n '1,260p' .github/workflows/build.yml
command -v semgrep
semgrep --version
docker ps
curl -sS http://127.0.0.1:9000/api/system/status
curl -I http://127.0.0.1:8082
```

Then inspect the GitHub Actions runner status and run the workflow manually. Report
any mismatch between this handoff and the new device before changing the pipeline.
