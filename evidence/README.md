# Validation evidence

[validation-summary.json](validation-summary.json) was generated from recorded results in the original private lab. Its fields are explicitly selected; public IPs, browser URLs, raw logs and user device details were excluded.

The principal purple-team run is `e5ef821f0b56`, recorded on **27 September 2026**. Its original source files were:

```text
deployment/results/purple-e5ef821f0b56/
  host-tests.json
  web-detect.json
  web-prevent.json
  normal-traffic-retest.json
  suricata-events.json
  wazuh-events.json
deployment/results/ips-http-tests.json
```

The original files remain private. This summary is a curated record, not an independently signed attestation or a complete log archive. Timestamps are retained as recorded; event occurrence and client request completion can have different times. Client timeouts complete after the sensor has already seen the request.

## What these records support

| Observation | Supporting fields |
|---|---|
| Purple request reached the app in alert mode | Detection HTTP `404`, curl exit `0`; SID `1000003` action `allowed` |
| Matching request blocked after manual response | Prevention HTTP `000`, curl exit `28`; SID `1000003` action `blocked`, Wazuh `100110` |
| Normal traffic remained available | Subsequent health HTTP `200`, exit `0` |
| File creation and modification detected | Wazuh `554` and `550` |
| Invalid SSH user detected | Wazuh `5710` |
| Service-account sudo attempt denied and detected | Host exit `1`, `denied: true`; Wazuh `100121` |
| Selected private network ports filtered | Expected and observed reachability for six SIEM ports |
| Original IPS test kept normal and identity traffic available | Historical health and OIDC discovery HTTP `200` checks |

The script's existence does not prove execution. These observations apply to the recorded run and selected checks. They do not prove protection against unrelated attacks or the current state of cloud resources.

## Add visual evidence before publication

Existing raw screenshots and videos were deliberately excluded because they can show deployment URLs, administrator source addresses or personal details. Capture or manually redact a small set of authentic screenshots and review them before placing them here:

1. Azure subnet view showing the network zones.
2. Authorized application workspace versus role-denied page.
3. Wazuh alert with the controlled signature and `allowed` action.
4. Wazuh alert with rule `100110` and `blocked` action.
5. Terminal showing a successful normal-traffic health check after blocking.

Do not publish passwords, authenticator QR codes, TOTP seeds, session cookies, bearer tokens, account pages, or full subscription identifiers. Preserve event times, rule IDs and outcomes so the images still support the claims. Never substitute generated images for evidence of a real execution.

See [the demo guide](../docs/demo.md) for a short sequence suitable for a portfolio video.
