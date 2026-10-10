# Architecture and scope

## Reference design versus deployed lab

The original project started from an enterprise Azure architecture containing perimeter firewalls, multiple network zones, Windows domain services, centralized security monitoring and purple-team exercises. The deployed environment is a smaller, student-budget implementation of selected controls.

The public diagram describes that implementation. It does not claim that every component in the enterprise reference diagram was deployed.

## Addressing and workloads

| VNet | Subnet | Address range | Occupancy |
|---|---|---|---|
| `vnet-pfa` | `snet-dmz` | `10.0.1.0/24` | Reserved |
| `vnet-pfa` | `snet-users` | `10.0.2.0/24` | Reserved |
| `vnet-pfa` | `snet-servers` | `10.0.3.0/24` | Services VM, `10.0.3.10` |
| `vnet-pfa` | `snet-mgmt` | `10.0.4.0/24` | Reserved |
| `vnet-pfa` | `snet-monitor` | `10.0.5.0/24` | SIEM VM, `10.0.5.10` |
| `vnet-pfa` | `snet-test` | `10.0.6.0/24` | Reserved |
| `vnet-pfa-domain` | `snet-mgmt` | `10.1.4.0/24` | Samba DC, `10.1.4.10` |
| `vnet-pfa-domain` | `snet-servers` | `10.1.3.0/24` | Windows member, `10.1.3.10` |

All private addresses are design values. The public configuration uses documentation-only public addresses, which must be replaced locally before use.

| VM | Original region | Original size | Purpose |
|---|---|---|---|
| `vm-pfa-services` | Sweden Central | `Standard_B2as_v2` | Caddy, Keycloak, PostgreSQL, Flask, Suricata, Wazuh agent, local restic exercise |
| `vm-pfa-siem` | Sweden Central | `Standard_B4as_v2` | Wazuh manager, indexer, dashboard, Filebeat and Caddy |
| `vm-pfa-dc` | Spain Central | `Standard_B2as_v2` | Samba AD/DC, internal DNS and Wazuh agent |
| `vm-pfa-windows` | Spain Central | `Standard_B2as_v2` | Windows Server 2022 domain member, IIS, SMB and Wazuh agent |

The core needs six vCPUs with these sizes; the optional domain extension adds four. Available student quota and permitted regions must be checked before deployment. Two regions increased latency and peering costs; they did not provide resilience. The public templates expose region parameters but retain the tested names, addressing and VM sizes.

## Network boundaries

Each subnet is associated with an NSG. Explicit rules allow the intended traffic and deny other flows before the broad default VNet rules. The core compute deployment updates the server and monitoring NSGs after the foundation stage; the stages must run in order.

- Administrative SSH, RDP and most public web access are limited to an administrator IPv4 `/32` source.
- HTTP `80` on the services and SIEM VMs remains public for ACME HTTP certificate validation and HTTPS redirects. This is an intentional exception, not a private-only deployment.
- Agents send events to the SIEM over private addresses using `1514`; enrollment uses `1515`.
- The Wazuh indexer and dashboard backend are not exposed as broadly reachable public services. Caddy provides HTTPS to the dashboard.
- Domain DNS, directory and Windows member flows use the domain VNet and explicit peering rules.
- Internet package downloads on `80/443`, DNS, time synchronization and Azure platform communication remain permitted where configured.

Peering enables private connectivity; it does not remove NSG enforcement. The bounded discovery results demonstrate six specific port checks from one source VM, not a complete network penetration test.

## Three distinct identity planes

1. **Azure management:** the existing subscription account and its Azure permissions create and manage resources. Entra directory administration was not available. Open-source tools cannot replace Azure's management-plane identity requirements.
2. **Application identity:** Keycloak realm `pfa` issues OIDC identity tokens. The `pfa-portal` confidential client uses the authorization-code flow and PKCE. A mapper adds realm roles to the identity claims. The Flask application requires `lab-user` for the workspace.
3. **Operating-system identity:** Samba provides AD-compatible domain services for `pfa.test`. The Windows VM is a domain member; `LabUsers` receives read access to the encrypted SMB share.

Keycloak and Samba maintain separate accounts. No LDAP federation, cross-plane SSO or Entra Conditional Access is claimed.

Authentication verifies who the user is; authorization decides what that user may access. `student` has `lab-user`. `visitor` can authenticate but receives HTTP `403` at the protected workspace. Both are synthetic accounts. TOTP codes come from an enrolled authenticator; they are not emailed passwords.

## TLS termination and IPS inspection

```mermaid
sequenceDiagram
    participant Browser
    participant Caddy
    participant Suricata as Suricata / NFQUEUE
    participant App as Flask on loopback:8000
    Browser->>Caddy: HTTPS request (encrypted on network)
    Caddy->>Suricata: Decrypted HTTP on loopback
    alt Signature action is alert
        Suricata->>App: Forward matching request
        App-->>Browser: Application response through Caddy
    else Signature action is drop
        Suricata--xApp: Drop matching traffic
        Note over Browser,App: Client times out; confirm blocked event and healthy normal traffic
    end
```

External web packets and loopback TCP `8000` packets are queued to NFQUEUE `0`. URI signatures are effective on the post-TLS loopback HTTP path. Suricata cannot read URLs inside the external encrypted TLS stream.

The queue uses `--queue-bypass`: traffic can continue when no process listens to the queue. This improves demo availability but makes the IPS **fail-open**. It is not a hardened enterprise perimeter or a sensor monitoring arbitrary Azure east-west traffic.

## Operational limits

- One SIEM VM; no redundant indexer or failover.
- Public IPs, disks and peering can cost money even after VM compute is stopped.
- Core templates include daily shutdown schedules; the recorded domain deployment did not support that schedule mechanism. Explicitly deallocate all four machines after the demonstration.
- The local restic repository is on the same VM as the data; VM loss can lose both.
- SMB encryption and permissions were configured, but a complete interactive allow/deny matrix was not recorded.
- Student deployment findings are not proof of production compliance.

These constraints are part of the project's engineering discussion, rather than features to conceal in a portfolio.
