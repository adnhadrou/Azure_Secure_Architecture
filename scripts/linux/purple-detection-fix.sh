#!/usr/bin/env bash
set -euo pipefail
cat >/var/ossec/etc/rules/pfa_purple_rules.xml <<'EOF'
<group name="pfa,purple_team,pam,">
  <rule id="100121" level="6">
    <decoded_as>pam</decoded_as>
    <match type="pcre2">pam_unix\(sudo:auth\): auth could not identify password for \[pfa-app\]</match>
    <description>PFA application account: non-interactive sudo authentication denied</description>
    <group>authentication_failed,</group>
  </rule>
</group>
EOF
chown root:wazuh /var/ossec/etc/rules/pfa_purple_rules.xml
chmod 640 /var/ossec/etc/rules/pfa_purple_rules.xml
/var/ossec/bin/wazuh-analysisd -t
printf '%s\n' 'Sep 14 16:55:18 vm-pfa-services sudo[4378]: pam_unix(sudo:auth): auth could not identify password for [pfa-app]' | /var/ossec/bin/wazuh-logtest -U 100121:6:pam
systemctl restart wazuh-manager
echo 'Detection improvement installed; a fresh real sudo denial must still be verified.'
