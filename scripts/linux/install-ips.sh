#!/usr/bin/env bash
set -euo pipefail
mkdir -p /var/log/pfa-deployment /etc/suricata/pfa-ips-backup
exec > >(tee -a /var/log/pfa-deployment/ips.log) 2>&1
echo "START IPS $(date --iso-8601=seconds)"
suricata --build-info | grep -i NFQ
command -v iptables
test -f /etc/suricata/pfa-ips-backup/suricata.yaml || cp -p /etc/suricata/suricata.yaml /etc/suricata/pfa-ips-backup/suricata.yaml
cat >/etc/suricata/rules/pfa-ips.rules <<'EOF'
alert http any any -> any any (msg:"PFA controlled IDS test"; flow:established,to_server; http.uri; content:"/pfa-ids-check"; sid:1000001; rev:1;)
drop http any any -> any any (msg:"PFA IPS blocked controlled request"; flow:established,to_server; http.uri; content:"/pfa-ips-block"; startswith; sid:1000002; rev:1;)
EOF
python3 - <<'PY'
import yaml
from pathlib import Path
t=yaml.safe_load(Path('/etc/suricata/suricata.yaml').read_text())
t['rule-files']=['pfa-ips.rules']
t.setdefault('stream',{})['inline']=True
t['default-log-dir']='/var/log/suricata'
Path('/etc/suricata/pfa-ips.yaml').write_text('%YAML 1.1\n---\n'+yaml.safe_dump(t,sort_keys=False))
PY
suricata -T -c /etc/suricata/pfa-ips.yaml -q 0
cat >/usr/local/sbin/pfa-ips-netfilter <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
remove_hooks() {
 while iptables -w -C INPUT -j PFA_IPS_IN 2>/dev/null; do iptables -w -D INPUT -j PFA_IPS_IN; done
 while iptables -w -C OUTPUT -j PFA_IPS_OUT 2>/dev/null; do iptables -w -D OUTPUT -j PFA_IPS_OUT; done
}
if [ "${1:-}" = stop ]; then
 remove_hooks
 exit 0
fi
iptables -w -N PFA_IPS_IN 2>/dev/null || true
iptables -w -N PFA_IPS_OUT 2>/dev/null || true
# Only these project-owned chains are reset. Docker/system chains remain intact.
iptables -w -F PFA_IPS_IN
iptables -w -F PFA_IPS_OUT
# External host web traffic, both directions. TLS contents remain encrypted here.
iptables -w -A PFA_IPS_IN ! -i lo -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -w -A PFA_IPS_OUT ! -o lo -p tcp -m multiport --sports 80,443 -j NFQUEUE --queue-num 0 --queue-bypass
# Inspect each loopback packet once, after Caddy terminates TLS, including replies.
iptables -w -A PFA_IPS_IN -i lo -p tcp -m multiport --ports 8000 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -w -C INPUT -j PFA_IPS_IN 2>/dev/null || iptables -w -I INPUT 1 -j PFA_IPS_IN
iptables -w -C OUTPUT -j PFA_IPS_OUT 2>/dev/null || iptables -w -I OUTPUT 1 -j PFA_IPS_OUT
EOF
chmod 750 /usr/local/sbin/pfa-ips-netfilter
mkdir -p /etc/systemd/system/suricata.service.d
cat >/etc/systemd/system/suricata.service.d/pfa-ips.conf <<'EOF'
[Service]
Type=simple
PIDFile=
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/pfa-ips.yaml -q 0
Restart=on-failure
RestartSec=5
EOF
cat >/etc/systemd/system/pfa-ips-netfilter.service <<'EOF'
[Unit]
Description=PFA host web IPS Netfilter queues
After=network-online.target suricata.service
Wants=network-online.target suricata.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/pfa-ips-netfilter start
ExecStop=/usr/local/sbin/pfa-ips-netfilter stop
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart suricata
sleep 3
systemctl is-active suricata
systemctl enable --now pfa-ips-netfilter
systemctl restart wazuh-agent
iptables -w -nvL PFA_IPS_IN
iptables -w -nvL PFA_IPS_OUT
echo "COMPLETE IPS $(date --iso-8601=seconds)"
