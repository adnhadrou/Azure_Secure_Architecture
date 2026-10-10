# Local publication checks

The public package was checked locally during preparation. These checks do not contact Azure and do not run the installation or deployment scripts.

| Check | Result |
|---|---|
| JSON syntax and basic ARM parameter references | Passed: 7 JSON files |
| Python syntax | Passed: 6 Python files plus 8 embedded Python blocks |
| Custom Wazuh XML | Passed: 3 files; examples match installer content |
| Relative documentation links | Passed |
| Selected publication checks | Passed: no detected private-key material, JWTs, personal Windows paths, subscription resource IDs or unexpected public IPv4 addresses |
| PowerShell parser | Passed: 5 scripts; none executed |
| Bash parser | Passed: 7 scripts; none executed |
| Evidence collector behavior | Passed: 4 offline tests using synthetic mixed logs |
| Historical result consistency | Passed: recorded detection, blocked-event and normal-traffic outcomes present |

The checks are intentionally bounded. The publication scan is not a comprehensive credential scanner. Cloud template validation, a full deployment from the reorganized package, interactive OIDC/MFA checks and GitHub-hosted workflow execution were not performed during this preparation.

The historical cloud observations are documented separately in [evidence](../evidence/README.md). [Public-export changes](public-export-changes.md) explains which source artifacts were adjusted for reuse.
