# Investigation Playbook

## Purpose

Use this playbook to triage unusual web activity surfaced by the Splunk searches in this repository.

## Triage flow

1. Validate the alert or search result.
2. Identify the source IP, requested paths, user agent and time window.
3. Compare activity with normal request volume for the same period.
4. Determine whether the requests indicate:
   - normal browsing,
   - broken application behaviour,
   - automated scanning,
   - credential abuse,
   - enumeration,
   - exploitation attempts.
5. Correlate with authentication, reverse proxy, firewall or endpoint logs where available.
6. Record the evidence and assessment.
7. Escalate when the activity is confirmed malicious or materially impacts service availability.

## Example evidence to capture

- first and last observed timestamp
- source IP
- request count
- unique paths
- HTTP methods
- HTTP status codes
- user agent
- affected service
- related authentication events
- remediation actions

## Containment examples

Depending on the environment and confidence level:

- block or rate-limit a confirmed hostile source
- disable or protect exposed administrative paths
- rotate exposed credentials
- isolate a compromised endpoint
- engage the service owner or incident response function

## Portfolio note

This playbook is deliberately generic and contains no production procedures or employer-specific information.
