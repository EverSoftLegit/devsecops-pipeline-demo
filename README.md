# DevSecOps Pipeline Demo

![security-pipeline](https://github.com/EverSoftLegit/devsecops-pipeline-demo/actions/workflows/security-pipeline.yml/badge.svg)

A small Flask notes API with a GitHub Actions pipeline that runs security checks on every push and pull request. The app is deliberately simple; the point of the repository is the pipeline and the reasoning behind each gate.

## Pipeline gates

| Job | Tool | Catches | Does not catch |
|---|---|---|---|
| Unit tests | pytest | Regressions in behaviour, including security behaviour the app claims (headers, input validation, parameterised SQL, error handling) | Anything not written as a test |
| SAST | [Bandit](https://bandit.readthedocs.io/) | Insecure Python patterns, e.g. SQL built with string formatting, `debug=True`, `subprocess` with `shell=True`, weak hashing | Logic flaws, broken access control, issues needing data-flow across files |
| SCA | [pip-audit](https://pypi.org/project/pip-audit/) | Pinned dependencies with published advisories (PyPI/OSV) | Vulnerabilities not yet published; flaws in your own code |
| Secrets | [gitleaks](https://github.com/gitleaks/gitleaks) | API keys, tokens and private keys anywhere in Git history | Secrets in formats it has no rule for; secrets stored outside the repo |
| DAST | [OWASP ZAP](https://www.zaproxy.org/) baseline | Missing security headers, information leakage and other issues visible in HTTP responses, against the app running inside the CI runner | Anything requiring active attacks; endpoints the spider doesn't reach |

The ZAP report is summarised on the run page using the parser and report builder from my [authorised-security-assessment-toolkit](https://github.com/EverSoftLegit/authorised-security-assessment-toolkit), pinned to a specific commit. The raw HTML/JSON reports are attached to each run as artifacts.

## Design choices

- **Least privilege:** the workflow token is `contents: read` only.
- **Fail on what the app guarantees, report the rest:** ZAP rules for controls the app explicitly implements (`zap/rules.tsv`) are set to `FAIL`, so a regression breaks the build. Other ZAP alerts are reported as warnings for a human to triage instead of blocking every build.
- **Pinned versions:** application dependencies are pinned exactly in `requirements.txt`, gitleaks is pinned to a release, and the toolkit is pinned to a commit SHA. Dependabot (`.github/dependabot.yml`) proposes updates weekly for both Python packages and GitHub Actions.
- **Weekly scheduled run:** advisories are published against versions that haven't changed, so the pipeline also runs every Monday.
- **The scan target is the app in the runner:** ZAP only scans `127.0.0.1` inside the CI job. No external systems are scanned.

## The app's own security controls

`app/main.py` uses parameterised SQL queries, allow-list input validation with length limits, a 16 KB request-body limit, JSON-only generic error responses (no stack traces), and security headers on every response, including error pages. `tests/test_app.py` tests each of these.

## Run locally

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
bandit -r app
pip-audit -r requirements.txt
python -m app.main          # serves on http://127.0.0.1:5000
```

## See a gate fail

To check the gates work, open a branch and add an insecure change, for example this in `app/main.py`:

```python
@app.get("/search")
def search() -> Any:
    q = request.args.get("q", "")
    return jsonify(get_db().execute(f"SELECT id, title FROM notes WHERE title = '{q}'").fetchall())
```

Open a pull request: the Bandit job fails with `B608` (SQL built from a string). Downgrading Flask in `requirements.txt` to `2.2.2` makes pip-audit fail. Don't merge either change.

## Limitations

- ZAP baseline is a passive scan. For an API, an OpenAPI-driven `zap-api-scan` with active rules would cover far more.
- The app runs on Flask's development server in CI. A production deployment would run behind a WSGI server such as Gunicorn, which also changes the `Server` header that ZAP reports.
- Third-party actions are pinned to major-version tags for readability. Pinning to full commit SHAs is stronger against a compromised action release.
- There is no authentication, so access-control testing is out of scope for this demo.

## License

MIT
