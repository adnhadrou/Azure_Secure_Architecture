# Deployment guide

This guide reconstructs the staged lab. The original environment was tested; the reorganized public package has only been checked offline. Treat the templates and installers as reviewed starting points, not a guaranteed unattended deployment.

## 1. Prerequisites and scope

- An Azure subscription where you can deploy network and VM resources. Directory administrator access is not required for local Keycloak/Samba accounts. Azure management still requires your authorized Azure identity.
- Azure CLI, Python 3.10+ and PowerShell. OpenSSH client and curl are needed for the exercise. The published workflow uses PowerShell 7, while the original operator used Windows PowerShell.
- Allowed regions, sufficient vCPU quota, VM-size availability and enough remaining credit for the selected sizes, disks, public IPv4 addresses and peering.
- An administrator public IPv4 address and a stable SSH key pair. Restrict administrative source access to that exact IPv4 `/32`.
- Fresh Ubuntu 22.04 lab VMs; Windows Server 2022 for the optional domain member.

There are two useful scopes: **core lab** (services + SIEM, six vCPUs) and **domain extension** (Samba + Windows, four more). Provision the core first. For a student account, check cost and quota in the portal before applying anything. The historical core region was Sweden Central and the domain region Spain Central because of account restrictions; use permitted regions in your own account.

## 2. Prepare private local configuration

From the repository root:

```powershell
New-Item -ItemType Directory -Force .local, .local/keys | Out-Null
Copy-Item config/core.parameters.example.json .local/core.parameters.json
Copy-Item config/domain.parameters.example.json .local/domain.parameters.json
Copy-Item config/lab.example.json config/lab.local.json
ssh-keygen -t ed25519 -f .local/keys/lab_ed25519
```

Edit the local files:

- `adminSource`: your actual public IPv4 `/32`; never `0.0.0.0/0`.
- `sshPublicKey`: the full single-line contents of the generated `.pub` file. Azure guest SSH user is `labadmin`.
- `location` / `domainLocation`: allowed regions. Core VM and network regions must match.
- `shutdownTime`: four digits, for example `1900`; the template uses UTC.
- `windowsAdminPassword`: locally generated strong password for the optional Windows administrator; keep the file private.
- After provisioning, fill the actual services/SIEM public addresses and application HTTPS URL in `config/lab.local.json`.

The example public IPs are reserved documentation addresses; they cannot reach the lab. The private addressing is fixed by this design. Changing it requires updating templates, agents, domain setup and the bounded port test together.

Do not add `.local` or `*.local.json` to Git. Protect local credential files with user-only filesystem permissions. A `.gitignore` reduces accidental staging but does not encrypt files or remove already committed secrets.

## 3. Authenticate and inspect the subscription

```powershell
az login
az account list --output table
az account set --subscription '<YOUR_SUBSCRIPTION_NAME_OR_ID>'
az account show --output table
az vm list-usage --location '<CORE_REGION>' --output table
az vm list-skus --location '<CORE_REGION>' --resource-type virtualMachines --all --output table
```

Inspect subscription policy and allowed locations in the portal. Do not assume a size listed in the regional catalogue is allowed by your subscription or available at deployment time. These commands are read-only.

Choose a dedicated resource group for the lab. Creating it is a separate deliberate step:

```powershell
az group create --name rg-security-lab --location '<CORE_REGION>'
```

## 4. Review then apply the network foundation

The foundation creates six core subnets and their NSGs. Create a `.local/network.parameters.json` parameter file with just `location` if using a location different from the resource group's location.

```powershell
.\scripts\deploy.ps1 -Stage Network -ResourceGroup rg-security-lab
# To apply after inspecting the plan:
.\scripts\deploy.ps1 -Stage Network -ResourceGroup rg-security-lab -Apply
```

The default command runs Azure `what-if`; it does not deploy resources. What-if still requires a signed-in account, an existing resource group, and Azure permissions. The `-Apply` command creates or changes resources and incurs costs.

## 5. Deploy the core VMs

```powershell
.\scripts\deploy.ps1 -Stage Core -ResourceGroup rg-security-lab -ParametersFile .local/core.parameters.json
.\scripts\deploy.ps1 -Stage Core -ResourceGroup rg-security-lab -ParametersFile .local/core.parameters.json -Apply
az vm list --resource-group rg-security-lab --show-details --output table
```

The template creates Linux services/SIEM VMs, NICs, public IPs and shutdown schedules. It updates the server/monitor NSGs, including application and agent rules. The schedules do not eliminate disk and public-IP costs.

Verify the host key for each VM using a trusted source, such as a verified Azure guest/console session, before approving the first SSH connection. Keep a known-hosts file for subsequent automation. `ssh-keyscan` retrieves a key but does not prove its authenticity.

For the first verified connection to each Linux VM, save its approved key in the file used by the exercise:

```powershell
ssh -i .local/keys/lab_ed25519 -o UserKnownHostsFile=.local/keys/known_hosts labadmin@<VM_PUBLIC_IP>
```

For subsequent `ssh` and `scp` commands below, add `-o UserKnownHostsFile=.local/keys/known_hosts -o StrictHostKeyChecking=yes` to use that same verified file.

## 6. Install the SIEM first

From the laptop, substitute your own addresses:

```powershell
scp -i .local/keys/lab_ed25519 scripts/linux/install-siem.sh labadmin@<SIEM_PUBLIC_IP>:/home/labadmin/
ssh -i .local/keys/lab_ed25519 labadmin@<SIEM_PUBLIC_IP>
```

On the **SIEM VM**:

```bash
sudo bash /home/labadmin/install-siem.sh <SIEM_PUBLIC_IP>
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat caddy
```

The installer downloads the Wazuh 4.14 assistant, installs the all-in-one components, binds the dashboard backend to loopback and exposes it through Caddy HTTPS. It adds the custom application rules.

Wazuh generated credentials stay under `/root/pfa-private/`. Read them privately over your authenticated terminal when needed; do not paste them into issue threads or recordings. Logs are under `/var/log/pfa-deployment/`. A printed installer checksum is a record of the downloaded file, not a comparison against an independently verified checksum.

## 7. Install application, identity and the initial sensor

From the laptop:

```powershell
scp -i .local/keys/lab_ed25519 app/demo-app.py scripts/linux/install-services.sh labadmin@<SERVICES_PUBLIC_IP>:/home/labadmin/
ssh -i .local/keys/lab_ed25519 labadmin@<SERVICES_PUBLIC_IP>
```

On the **services VM**:

```bash
sudo bash /home/labadmin/install-services.sh <SERVICES_PUBLIC_IP>
sudo systemctl is-active pfa-app caddy docker suricata wazuh-agent
```

The fresh-install script generates passwords/secrets, creates the Keycloak realm, starts PostgreSQL and Keycloak containers, installs the Flask app under a dedicated system user, configures Caddy, adds the Wazuh log/FIM inputs and performs a local restic restore comparison.

URLs follow this lab convention:

```text
https://app.<SERVICES_PUBLIC_IP>.sslip.io
https://idp.<SERVICES_PUBLIC_IP>.sslip.io
https://siem.<SIEM_PUBLIC_IP>.sslip.io
```

DNS resolution and public HTTP certificate validation must work. Your browser must originate from the permitted administrator IP for restricted HTTPS access. No live URLs are provided in this repository.

Sign in to Keycloak and the application with locally generated synthetic credentials. Enroll `student` and `visitor` in an authenticator. Verify `student` can open the workspace and `visitor` receives HTTP `403` after authentication. Do not record enrollment QR codes.

After verifying successful first realm import, remove the secret-bearing import JSON:

```bash
sudo rm -- /opt/pfa-identity/import/pfa-realm.json
```

The compose configuration still holds generated secrets protected by file permissions; this is a lab design. Do not rerun initial installers blindly after a partial failure. The public copy adds first-install guards but does not provide a complete resumable deployment system.

## 8. Enable host IPS and its Wazuh rule

Upload `scripts/linux/install-ips.sh` to services, and `install-ips-wazuh.sh` and `purple-detection-fix.sh` to SIEM using the same SCP pattern.

On services:

```bash
sudo bash /home/labadmin/install-ips.sh
sudo systemctl is-active suricata pfa-ips-netfilter
sudo iptables -nvL PFA_IPS_IN
```

On SIEM:

```bash
sudo bash /home/labadmin/install-ips-wazuh.sh
sudo bash /home/labadmin/purple-detection-fix.sh
sudo /var/ossec/bin/wazuh-analysisd -t
```

The initial IPS install resets its small project rules file. Run it before the purple workflow; rerunning it later removes SID `1000003` until `Prepare` adds it again. It requires NFQUEUE support and a working services installation. Read [the scope and fail-open tradeoff](architecture.md) before using it.

For rollback, upload and run `rollback-ips.sh` on services. It removes only the project's queue hooks and override, then returns to the initial passive sensor service configuration. It does not undo Azure NSGs.

## 9. Optional Samba/Windows extension

```powershell
.\scripts\deploy.ps1 -Stage Domain -ResourceGroup rg-security-lab -ParametersFile .local/domain.parameters.json
.\scripts\deploy.ps1 -Stage Domain -ResourceGroup rg-security-lab -ParametersFile .local/domain.parameters.json -Apply
```

This template creates the domain VNet, DC/Windows VMs and two peering directions. The fixed core VNet must already exist in the same resource group.

Upload `install-domain.sh` to the **DC VM**, then run:

```bash
sudo bash /home/labadmin/install-domain.sh
sudo systemctl is-active samba-ad-dc wazuh-agent
```

Confirm the Windows NIC uses private domain DNS `10.1.4.10`. If it is absent from the NIC's effective configuration, configure it before joining:

```powershell
az network nic update --resource-group rg-security-lab --name nic-vm-pfa-windows --dns-servers 10.1.4.10
```

Renew guest network settings or reboot as appropriate, then confirm `Resolve-DnsName pfa.test` resolves through domain DNS. Retrieve the generated Samba administrator password privately on the DC. Connect to Windows by RDP using its local `labadmin` account and the local password supplied to the ARM template. Transfer the two `scripts/windows/` files to that VM.

In an elevated **Windows VM** PowerShell:

```powershell
$JoinPassword = Read-Host 'Samba domain administrator password' -AsSecureString
.\configure-windows.ps1 -DomainPassword $JoinPassword
$JoinPassword = $null
Restart-Computer
# After reconnecting, in an elevated session:
.\finish-windows.ps1
Test-ComputerSecureChannel
Get-SmbShareAccess -Name PFAData
```

The script verifies the Wazuh MSI signature, installs IIS/SMB and the agent, and joins the domain. The post-restart script verifies the secure channel and configures encrypted SMB with matching NTFS permissions. Manually test file access as both authorized and unauthorized domain accounts before claiming full SMB authorization coverage.

## 10. Run the exercise and inspect evidence

Configure and verify your SSH known-hosts file, then follow [the detection workflow](detection-and-response.md) and [demo sequence](demo.md). Runtime outputs go to ignored `.local/results/`. They may still contain sensitive values; inspect and sanitize before any manual publication.

## 11. Stop compute and control costs

After the demo, explicitly deallocate every VM:

```powershell
az vm deallocate -g rg-security-lab -n vm-pfa-services
az vm deallocate -g rg-security-lab -n vm-pfa-siem
az vm deallocate -g rg-security-lab -n vm-pfa-dc
az vm deallocate -g rg-security-lab -n vm-pfa-windows
```

Only run commands for resources you actually created. Guest shutdown alone may leave compute allocated. Review Cost Management and remaining credits. Disks, IPs and other resources can continue billing after compute deallocation. When the lab is no longer needed, use the portal to review and delete its dedicated resource group; deletion is destructive and should be a separate decision after exporting needed evidence.
