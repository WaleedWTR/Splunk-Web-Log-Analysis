# Detection Engineering Notes

The hunting searches in this project are intentionally simple so they are easy to understand and reproduce.

## Production considerations

Before promoting any search into an alert:

- establish a baseline for normal traffic
- tune thresholds to the application
- exclude authorised scanners and monitoring systems
- enrich source IPs where appropriate
- correlate with authentication and endpoint telemetry
- define severity and ownership
- define an escalation route
- measure false-positive rate
- review detections after application changes

## Example mapping

| Detection | Possible behaviour | Useful follow-up |
| --- | --- | --- |
| High-volume 404s | Enumeration / discovery | Review paths, source reputation and rate |
| Scanner user agent | Automated security scanning | Validate whether source is authorised |
| Sensitive path probes | Discovery / exploitation attempt | Check WAF, proxy and application logs |
| Burst request rate | Automation / DoS / scraping | Compare baseline and rate-limit where justified |

## Engineering principle

A detection is not complete when the query works. It also needs ownership, context, tuning, validation, response guidance and a feedback loop.
