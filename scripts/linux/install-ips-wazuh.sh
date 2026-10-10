#!/usr/bin/env bash
set -euo pipefail
cat >/var/ossec/etc/rules/pfa_ips_rules.xml <<'EOF'
<group name="pfa,ids,ips,">
  <rule id="100110" level="10">
    <if_sid>86601</if_sid>
    <field name="alert.action">^blocked$</field>
    <description>Suricata IPS blocked a matching network request: $(alert.signature)</description>
    <group>network_block,</group>
  </rule>
</group>
EOF
chown root:wazuh /var/ossec/etc/rules/pfa_ips_rules.xml
chmod 640 /var/ossec/etc/rules/pfa_ips_rules.xml
/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
echo "COMPLETE WAZUH IPS RULE $(date --iso-8601=seconds)"
