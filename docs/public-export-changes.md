# What changed for public reuse

The original working lab was preserved. This repository is a separate export of selected implementation artifacts.

| Area | Public-package change |
|---|---|
| Scope | Removed private reports, Azure session state, keys, raw results, original account configuration and screenshots |
| Documentation | Replaced the mixed enterprise-reference README with the actual deployed student scope, limitations and measured results |
| ARM templates | Added region parameters; removed the domain template's unused shutdown parameter; retained resource names, VM sizes and private addressing |
| Purple orchestration | Replaced actual public addresses with local configuration; moved state/logs to ignored `.local/`; captured expected invalid-user SSH stderr without terminating early |
| Initial installation | Added basic existing-installation guards for services and SIEM; installers still require manual recovery after partial failure |
| Windows setup | Accept a `SecureString` domain-join password in the guest script instead of a plain-text parameter |
| Application | Added an optional `AUDIT_LOG_PATH` environment override; unchanged default log path and authorization behavior |
| Detections | Extracted custom XML examples from their installers; validate consistency between them |
| Evidence | Whitelisted fields from historical records; retained timestamps, rule IDs and outcomes |
| Validation | Added syntax/publication checks, evidence-selection tests and a GitHub workflow that never deploys Azure |

These publication changes were checked offline. They are not presented as a newly completed cloud deployment. The included historical evidence comes from the original lab execution, before this repository was reorganized.
