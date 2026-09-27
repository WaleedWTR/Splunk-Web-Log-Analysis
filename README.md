# Splunk Web Log Analysis

![Python tests](https://github.com/WaleedWTR/Splunk-Web-Log-Analysis/actions/workflows/python-tests.yml/badge.svg)

A practical observability and security analytics project showing how web server access logs can be ingested, searched, investigated and turned into operational insight in Splunk.

> **Portfolio note:** This repository is a sanitised demonstration project. Sample data and examples are synthetic and contain no employer, government or production information.

## What this project demonstrates

- ingesting web access logs into Splunk
- building repeatable SPL searches
- monitoring traffic and error trends
- identifying top requested resources
- detecting suspicious request patterns
- creating reusable hunting content
- documenting incident investigation workflows
- validating sample telemetry with Python
- testing code automatically with GitHub Actions

## Architecture

```text
Synthetic Web Logs
       |
       +------------------+
       |                  |
       v                  v
    Splunk              Python
       |                  |
       v                  v
  SPL Analytics      Validation Tests
       |
       +--> Availability / traffic
       +--> HTTP error analysis
       +--> Security hunting
       +--> Detection candidates
       |
       v
Dashboard + Investigation Playbook
```

## Repository structure

```text
.
├── .github/
│   └── workflows/
│       └── python-tests.yml
├── data/
│   └── sample_access.log
├── docs/
│   ├── detection-engineering-notes.md
│   └── investigation-playbook.md
├── scripts/
│   └── analyse_logs.py
├── spl/
│   ├── dashboard_queries.spl
│   ├── savedsearches.conf.example
│   └── security_hunting_queries.spl
├── tests/
│   └── test_analyse_logs.py
├── LICENSE
├── SECURITY.md
└── README.md
```

## Core dashboard searches

### Requests over time

```spl
index=web sourcetype=access_combined
| timechart span=5m count AS requests
```

### Top requested pages

```spl
index=web sourcetype=access_combined
| stats count AS requests BY uri_path
| sort - requests
| head 10
```

### HTTP error rate

```spl
index=web sourcetype=access_combined
| eval is_error=if(status>=400,1,0)
| timechart span=5m count AS total sum(is_error) AS errors
| eval error_rate=round((errors/total)*100,2)
```

### Requests by status class

```spl
index=web sourcetype=access_combined
| eval status_class=case(
    status>=500,"5xx",
    status>=400,"4xx",
    status>=300,"3xx",
    status>=200,"2xx",
    true(),"other")
| stats count BY status_class
```

## Security hunting

Included examples cover:

- high-volume 404 enumeration
- scanner-like user agents
- access to potentially sensitive paths
- unusually high request rates by source IP

The queries are deliberately understandable and tunable. They are examples for learning and portfolio demonstration, not production-ready detections.

## Local validation

The Python utility parses the synthetic access log and produces basic traffic and security metrics.

```bash
python scripts/analyse_logs.py
```

Run the automated tests with:

```bash
python -m pip install pytest
python -m pytest -q
```

GitHub Actions runs the tests when relevant code or data changes.

## How to reproduce in Splunk

1. Install Splunk Enterprise or use a Splunk lab environment.
2. Create an index named `web`.
3. Upload `data/sample_access.log`.
4. Set the sourcetype to `access_combined` or adjust the SPL to your parser.
5. Run the searches in `spl/dashboard_queries.spl`.
6. Add appropriate searches as dashboard panels.
7. Use `spl/security_hunting_queries.spl` for investigation exercises.
8. Review `spl/savedsearches.conf.example` for disabled alert examples and tune before use.

## Detection engineering approach

A useful detection needs more than a query. Before production use it should have:

- a baseline
- tuned thresholds
- known-good exclusions
- severity and ownership
- investigation guidance
- response criteria
- false-positive review
- periodic validation

See [Detection Engineering Notes](docs/detection-engineering-notes.md).

## Investigation workflow

The included [Investigation Playbook](docs/investigation-playbook.md) covers evidence capture, triage, correlation and example containment considerations.

## Skills demonstrated

**Splunk · SPL · Log Analysis · Security Monitoring · Detection Engineering · Incident Investigation · Python · GitHub Actions · Dashboard Design**

## Future improvements

- add field extraction examples for custom log formats
- add richer synthetic attack scenarios
- add threshold and risk-based detection examples
- add geo/IP enrichment guidance
- export a dashboard definition as source-controlled configuration
- add Universal Forwarder ingestion examples

## Disclaimer

This repository is intended for professional portfolio and learning purposes. All included data is synthetic and does not represent any real organisation, customer or production system.
