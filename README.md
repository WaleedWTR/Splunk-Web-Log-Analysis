# Splunk Web Log Analysis

A practical observability and security analytics project showing how web server access logs can be ingested, searched and turned into operational insight in Splunk.

> **Portfolio note:** This repository is a sanitised demonstration project. Sample data and examples are synthetic and contain no employer, government or production information.

## What this project demonstrates

- Ingesting web access logs into Splunk
- Building repeatable SPL searches
- Monitoring traffic and error trends
- Identifying top requested resources
- Detecting suspicious request patterns
- Turning raw events into an operational dashboard
- Documenting investigation and monitoring workflows

## Architecture

```text
Web Server Logs
      |
      v
Splunk Index
      |
      +--> Traffic / availability searches
      +--> Error-rate analysis
      +--> Security-focused detections
      |
      v
Dashboard + Investigation Workflow
```

## Repository structure

```text
.
├── README.md
├── data/
│   └── sample_access.log
├── spl/
│   ├── dashboard_queries.spl
│   └── security_hunting_queries.spl
└── docs/
    └── investigation-playbook.md
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

## Security hunting examples

The repository also includes searches for:

- repeated authentication failures
- high-volume 404 enumeration
- suspicious user agents
- unusual request rates by source IP
- requests to potentially sensitive paths

These are examples for learning and portfolio demonstration, not production-ready detections.

## How to reproduce

1. Install Splunk Enterprise or use a Splunk lab environment.
2. Create an index named `web`.
3. Upload `data/sample_access.log`.
4. Set the sourcetype to `access_combined` or adjust the SPL to your parser.
5. Run the searches in `spl/dashboard_queries.spl`.
6. Add the searches as dashboard panels.
7. Use `spl/security_hunting_queries.spl` for investigation exercises.

## Skills demonstrated

**Splunk · SPL · Log Analysis · Security Monitoring · Observability · Incident Investigation · Dashboard Design**

## Future improvements

- Add field extractions for custom log formats
- Add threshold-based alerts
- Add risk scoring
- Add geo/IP enrichment
- Export dashboard configuration as source-controlled XML/JSON
- Add automated ingestion using Universal Forwarder

## Disclaimer

This repository is intended for professional portfolio and learning purposes. All included data is synthetic and does not represent any real organisation, customer or production system.
