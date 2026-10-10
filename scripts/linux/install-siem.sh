#!/usr/bin/env bash
set -euo pipefail
umask 077
PUBLIC_IP="$1"
HOST="siem.${PUBLIC_IP}.sslip.io"
test ! -d /var/ossec || { echo "Existing Wazuh installation: resume manually."; exit 1; }
mkdir -p /root/pfa-private /var/log/pfa-deployment
exec >>/var/log/pfa-deployment/siem.log 2>&1
trap 'printf "FAILED line %s at %s\n" "$LINENO" "$(date --iso-8601=seconds)"' ERR
echo "START SIEM $(date --iso-8601=seconds)"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl ca-certificates gnupg debian-keyring debian-archive-keyring apt-transport-https
curl --fail --retry 3 -o /tmp/caddy.key https://dl.cloudsmith.io/public/caddy/stable/gpg.key
gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg /tmp/caddy.key
curl --fail --retry 3 -o /etc/apt/sources.list.d/caddy-stable.list https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt
chmod 644 /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy
cd /root/pfa-private
curl --fail --retry 3 -o wazuh-install.sh https://packages.wazuh.com/4.14/wazuh-install.sh
sha256sum wazuh-install.sh
# The assistant prints generated passwords. Its complete output stays root-only.
bash wazuh-install.sh -a > /root/pfa-private/wazuh-installer-output.log 2>&1
echo 'Wazuh assistant completed; credentials retained only in /root/pfa-private.'
chmod 600 /root/pfa-private/*
cp /etc/wazuh-dashboard/opensearch_dashboards.yml /root/pfa-private/dashboard-original.yml
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/wazuh-dashboard/opensearch_dashboards.yml')
text=p.read_text()
lines=[line for line in text.splitlines() if not line.startswith(('server.host:', 'server.port:', 'server.ssl.enabled:'))]
lines += ['server.host: 127.0.0.1','server.port: 5601','server.ssl.enabled: false']
p.write_text('\n'.join(lines)+'\n')
PY
cat >/var/ossec/etc/rules/pfa_rules.xml <<'XML'
<group name="pfa,">
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as><field name="pfa_event">^login_success$</field>
    <description>PFA application: successful authorized login</description>
  </rule>
  <rule id="100101" level="8">
    <decoded_as>json</decoded_as><field name="pfa_event">^access_denied$</field>
    <description>PFA application: authenticated user denied by role policy</description>
  </rule>
  <rule id="100102" level="5">
    <decoded_as>json</decoded_as><field name="pfa_event">^response_test$</field>
    <description>PFA controlled response exercise (synthetic event)</description>
  </rule>
</group>
XML
chown root:wazuh /var/ossec/etc/rules/pfa_rules.xml
chmod 640 /var/ossec/etc/rules/pfa_rules.xml
systemctl restart wazuh-manager wazuh-dashboard
cat >/etc/caddy/Caddyfile <<EOF
{
  acme_ca https://acme-v02.api.letsencrypt.org/directory
}
$HOST {
  reverse_proxy 127.0.0.1:5601
  header Strict-Transport-Security "max-age=86400"
}
EOF
chmod 644 /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile
systemctl enable --now caddy
systemctl reload caddy
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat caddy
dpkg-query -W wazuh-manager wazuh-indexer wazuh-dashboard filebeat caddy
echo "COMPLETE SIEM $(date --iso-8601=seconds) https://$HOST"
