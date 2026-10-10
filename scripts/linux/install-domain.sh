#!/usr/bin/env bash
set -euo pipefail
umask 077
mkdir -p /root/pfa-private /var/log/pfa-deployment
exec >>/var/log/pfa-deployment/domain.log 2>&1
trap 'printf "FAILED line %s at %s\n" "$LINENO" "$(date --iso-8601=seconds)"' ERR
echo "START DOMAIN $(date --iso-8601=seconds)"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y samba krb5-user winbind smbclient dnsutils curl ca-certificates gnupg
hostnamectl set-hostname pfa-dc
printf '\n10.1.4.10 pfa-dc.pfa.test pfa-dc\n' >>/etc/hosts
python3 - <<'PY'
import json,secrets
from pathlib import Path
p=Path('/root/pfa-private/domain-credentials.json')
if p.exists():
 raise SystemExit('Credentials already exist: resume the failed stage, do not reprovision the domain.')
p.write_text(json.dumps({k:secrets.token_urlsafe(28)+'!A9z' for k in ['administrator','domainstudent','ldap_bind']},indent=2))
PY
systemctl disable --now smbd nmbd winbind
if [ -f /etc/samba/smb.conf ]; then mv /etc/samba/smb.conf /root/pfa-private/smb.conf.before-domain; fi
ADPASS=$(python3 -c 'import json;print(json.load(open("/root/pfa-private/domain-credentials.json"))["administrator"])')
samba-tool domain provision --realm=PFA.TEST --domain=PFA --server-role=dc --dns-backend=SAMBA_INTERNAL --host-name=pfa-dc --host-ip=10.1.4.10 --use-rfc2307 --adminpass="$ADPASS"
unset ADPASS
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/samba/smb.conf')
t=p.read_text()
lines=[x for x in t.splitlines() if not x.strip().startswith('dns forwarder')]
lines.insert(1,'\tdns forwarder = 168.63.129.16')
p.write_text('\n'.join(lines)+'\n')
PY
systemctl disable --now systemd-resolved
if [ -L /etc/resolv.conf ]; then unlink /etc/resolv.conf; fi
printf 'search pfa.test\nnameserver 127.0.0.1\n' >/etc/resolv.conf
chmod 644 /etc/resolv.conf /etc/krb5.conf /etc/samba/smb.conf
systemctl unmask samba-ad-dc
systemctl enable --now samba-ad-dc
python3 - <<'PY'
import json,subprocess
d=json.load(open('/root/pfa-private/domain-credentials.json'))
for user,key in [('domainstudent','domainstudent'),('ldap-bind','ldap_bind')]:
 subprocess.run(['samba-tool','user','create',user,d[key]],check=True)
subprocess.run(['samba-tool','group','add','LabUsers'],check=True)
subprocess.run(['samba-tool','group','addmembers','LabUsers','domainstudent'],check=True)
PY
samba-tool domain passwordsettings set --complexity=on --min-pwd-length=14 --history-length=12
samba-tool domain level show
samba-tool domain passwordsettings show
host -t SRV _ldap._tcp.pfa.test 127.0.0.1
host -t SRV _kerberos._udp.pfa.test 127.0.0.1
samba-tool user list
curl --fail --retry 3 -o /tmp/wazuh-key https://packages.wazuh.com/key/GPG-KEY-WAZUH
gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg /tmp/wazuh-key
chmod 644 /usr/share/keyrings/wazuh.gpg
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' >/etc/apt/sources.list.d/wazuh.list
chmod 644 /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER=10.0.5.10 WAZUH_AGENT_NAME=pfa-dc apt-get install -y wazuh-agent
systemctl enable --now wazuh-agent
systemctl is-active samba-ad-dc wazuh-agent
echo "COMPLETE DOMAIN $(date --iso-8601=seconds)"
