# Put this project on GitHub and in a portfolio

## What to publish

Publish the **contents of this `azure-security-lab` folder**, not the parent working directory. It is a clean export containing reviewed source and sanitized results. The original directory also contains Azure session data, secret files, full logs and private reports that do not belong in a public repository.

Keep the source/configuration and documentation together. A README-only repository would explain the concept, but these templates, scripts, rules and result files let a reviewer inspect the actual engineering work.

Suggested repository name: `azure-security-lab`.

Suggested description:

> Azure student security lab: segmented networks, Keycloak IAM, Samba AD, Wazuh SIEM and Suricata IPS, with a validated purple-team detection-to-prevention workflow.

Suggested topics: `azure`, `cybersecurity`, `cloud-security`, `wazuh`, `suricata`, `keycloak`, `purple-team`, `infrastructure-as-code`, `powershell`, `python`.

## Publish with Git

First create an empty repository on GitHub. Do not initialize it with a different README. From **inside this export folder**, inspect and initialize:

```powershell
git init -b main
python tools/validate_repo.py
.\tools\Test-PowerShellSyntax.ps1
git add .
git diff --cached --stat
git diff --cached
git status
```

Review what is staged. No `.local`, private key, local account configuration, full Azure results or internship report should appear. You decide whether you own and can license the content; no open-source license has been selected on your behalf. Without a license, publication does not generally grant a reuse license.

When the staged content is ready:

```powershell
git commit -m "Document Azure security lab with templates, rules and validated results"
git remote add origin https://github.com/YOUR_USERNAME/azure-security-lab.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your account. These commands are instructions; the preparation process did not create a remote repository or push anything.

Alternatively, upload the folder's files through GitHub's web interface. Ensure `.github/workflows/validate.yml` and other hidden configuration files are included. The supplied ZIP is for transporting the repository contents; extract it before uploading the individual files.

## Before pinning the repository

- Check the README renders correctly, including both Mermaid diagrams.
- Check that the validation workflow passes on GitHub. Its checks are static and do not deploy Azure resources.
- Add a few manually reviewed authentic screenshots or a short demo video. Follow [the evidence guide](../evidence/README.md).
- Pin the repository to your GitHub profile and add its URL to your CV.
- Be ready to explain your architecture choices, the three separate identity planes, the IPS scope, and the evidence behind your result.

## CV wording

English:

> **Azure Security Lab** — Built a segmented Azure student environment integrating Keycloak OIDC/MFA, Samba AD, Wazuh monitoring and Suricata host IPS. Implemented custom detections and a controlled purple-team workflow, verifying blocked test traffic alongside service availability. Technologies: Azure ARM, PowerShell, Bash, Python, Wazuh, Suricata, Keycloak.

French:

> **Maquette de sécurité sur Azure** — Mise en place d'une infrastructure segmentée intégrant Keycloak (OIDC/MFA), Samba AD, Wazuh et Suricata en mode IPS sur un hôte. Création de règles de détection et validation d'un scénario Purple Team, avec vérification du blocage et de la disponibilité du service. Technologies : Azure ARM, PowerShell, Bash, Python, Wazuh, Suricata, Keycloak.

Use wording that reflects the work you understand and can defend. If tools or collaborators assisted implementation, describe your design, testing and investigation contributions honestly. Do not imply a production deployment or automated SOAR capability.
