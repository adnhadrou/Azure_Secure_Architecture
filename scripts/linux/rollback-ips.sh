#!/usr/bin/env bash
set -euo pipefail
# Remove only this project's queue hooks before returning Suricata to passive IDS.
systemctl disable --now pfa-ips-netfilter
/usr/local/sbin/pfa-ips-netfilter stop
if [ -f /etc/systemd/system/suricata.service.d/pfa-ips.conf ]; then
 mv /etc/systemd/system/suricata.service.d/pfa-ips.conf /etc/suricata/pfa-ips-backup/pfa-ips.conf.disabled
fi
systemctl daemon-reload
systemctl restart suricata
systemctl is-active suricata
echo "IPS rolled back to original IDS at $(date --iso-8601=seconds)"
