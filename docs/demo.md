# Three-minute practical demonstration

Use a screen recording with synthetic accounts. Avoid showing the Azure account page, secrets, authenticator enrollment, browser storage or unredacted address bars. Complete installation and health checks before recording.

| Time | Show | Explain |
|---|---|---|
| 0:00–0:25 | Architecture diagram and subnet list | Network zones and the smaller student implementation |
| 0:25–1:00 | Application sign-in, MFA challenge, authorized workspace, then visitor denial | Identity verification and application authorization are separate decisions |
| 1:00–1:25 | Wazuh agent list and application event | Endpoint/app events are centrally collected and decoded |
| 1:25–2:30 | Controlled purple probe before and after response, matching Wazuh events | Suricata detects first, then drops the selected signature after a manual change |
| 2:30–3:00 | Health check returns `200`, explain limits | Prevention did not break this normal request; host IPS and student lab scope |

## Exercise commands from the laptop

Run these from the repository root, after completing local configuration:

```powershell
.\scripts\purple-team.ps1 -Step Prepare
.\scripts\purple-team.ps1 -Step Exercise
.\scripts\purple-team.ps1 -Step Collect
```

Check the selected Wazuh events in `.local/results/purple-<run>/wazuh-events.json` and in the dashboard. If ingestion is delayed, wait briefly and collect again. Confirm the web probe was actually detected as `allowed` before continuing.

```powershell
.\scripts\purple-team.ps1 -Step Respond
.\scripts\purple-team.ps1 -Step Retest
.\scripts\purple-team.ps1 -Step Collect
```

Show SID `1000003`, action `blocked`, Wazuh rule `100110`, and the successful health check. Then:

```powershell
.\scripts\purple-team.ps1 -Step Cleanup
```

Cleanup only removes the run's canary file. The next `Prepare` returns the purple signature to alert mode. Keep all targets inside your own explicitly authorized lab.

## Suggested narration

> This project demonstrates how several security controls work together in Azure. The networks are separated by role, Keycloak verifies application users, and Wazuh centralizes endpoint and application events. An authenticated visitor can still be refused access because authorization depends on the assigned role. I then send a controlled request that Suricata recognizes. Initially it is allowed and logged. After reviewing the alert, I manually change that signature to prevention mode and repeat the request. The matching blocked alert and successful normal health check show that this particular control works without breaking the tested normal traffic.

For a French presentation:

> Cette maquette montre comment plusieurs contrôles de sécurité fonctionnent ensemble sur Azure. Les réseaux sont séparés selon leur rôle, Keycloak authentifie les utilisateurs et Wazuh centralise les événements. Un utilisateur authentifié peut être refusé si son rôle ne lui donne pas accès à la ressource. Je génère ensuite une requête de test reconnue par Suricata. Elle est d'abord autorisée et journalisée. Après vérification de l'alerte, je passe manuellement la règle en mode blocage et je refais le test. L'alerte de blocage et le contrôle de disponibilité permettent de valider ce scénario précis.

If a live component fails, use authentic recorded evidence and explain its date. Do not portray recorded results as a current live execution.
