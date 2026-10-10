#!/usr/bin/env bash
set -euo pipefail
umask 077
PUBLIC_IP="$1"
export PFA_PUBLIC_IP="$PUBLIC_IP"
test ! -e /root/pfa-private/credentials.json || { echo "Existing credentials: resume manually; do not reprovision."; exit 1; }
mkdir -p /root/pfa-private /var/log/pfa-deployment /opt/pfa-demo/data /var/log/pfa-app
exec >>/var/log/pfa-deployment/services.log 2>&1
trap 'printf "FAILED line %s at %s\n" "$LINENO" "$(date --iso-8601=seconds)"' ERR
echo "START SERVICES $(date --iso-8601=seconds)"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io docker-compose python3-venv python3-yaml curl ca-certificates gnupg suricata restic debian-keyring debian-archive-keyring apt-transport-https
curl --fail --retry 3 -o /tmp/caddy.key https://dl.cloudsmith.io/public/caddy/stable/gpg.key
gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg /tmp/caddy.key
curl --fail --retry 3 -o /etc/apt/sources.list.d/caddy-stable.list https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt
chmod 644 /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy
systemctl enable --now docker
id pfa-app >/dev/null 2>&1 || useradd --system --home /opt/pfa-demo --shell /usr/sbin/nologin pfa-app
chmod 755 /opt/pfa-demo /var/log/pfa-app
chown pfa-app:pfa-app /var/log/pfa-app
mkdir -p /opt/pfa-identity/import
python3 - <<'PY'
import json, os, secrets
from pathlib import Path
ip=os.environ['PFA_PUBLIC_IP']
base=Path('/opt/pfa-identity')
credentials={key:secrets.token_urlsafe(30) for key in ['admin_password','student_password','visitor_password','db_password','client_secret','app_secret','restic_password']}
credentials.update(admin_username='pfa-admin',student_username='student',visitor_username='visitor')
Path('/root/pfa-private/credentials.json').write_text(json.dumps(credentials,indent=2))
realm={
 'realm':'pfa','enabled':True,'displayName':'PFA Security Lab','sslRequired':'all',
 'registrationAllowed':False,'resetPasswordAllowed':False,'rememberMe':False,
 'bruteForceProtected':True,'failureFactor':5,'waitIncrementSeconds':60,'maxFailureWaitSeconds':900,
 'passwordPolicy':'length(14) and notUsername','eventsEnabled':True,'eventsExpiration':604800,
 'eventsListeners':['jboss-logging'],'adminEventsEnabled':True,'adminEventsDetailsEnabled':False,
 'roles':{'realm':[{'name':'lab-user','description':'Access to the protected PFA application'}]},
 'clients':[{'clientId':'pfa-portal','enabled':True,'protocol':'openid-connect','publicClient':False,
  'secret':credentials['client_secret'],'standardFlowEnabled':True,'directAccessGrantsEnabled':False,
  'serviceAccountsEnabled':False,'redirectUris':[f'https://app.{ip}.sslip.io/callback'],
  'webOrigins':[f'https://app.{ip}.sslip.io'],
  'attributes':{'post.logout.redirect.uris':f'https://app.{ip}.sslip.io/','pkce.code.challenge.method':'S256'},
  'protocolMappers':[{'name':'realm-roles','protocol':'openid-connect','protocolMapper':'oidc-usermodel-realm-role-mapper',
    'config':{'claim.name':'roles','jsonType.label':'String','multivalued':'true',
              'id.token.claim':'true','access.token.claim':'true','userinfo.token.claim':'true'}}]}],
 'users':[{'username':user,'enabled':True,'emailVerified':True,'email':user+'@pfa.invalid',
           'firstName':user.capitalize(),'lastName':'Demo','requiredActions':['CONFIGURE_TOTP'],
           'credentials':[{'type':'password','value':credentials[user+'_password'],'temporary':False}],
           'realmRoles':['lab-user'] if user=='student' else []} for user in ['student','visitor']]
}
(base/'import/pfa-realm.json').write_text(json.dumps(realm,indent=2))
compose={'version':'3.8','services':{
 'postgres':{'image':'postgres:17','restart':'unless-stopped','environment':{
   'POSTGRES_DB':'keycloak','POSTGRES_USER':'keycloak','POSTGRES_PASSWORD':credentials['db_password']},
   'volumes':['postgres-data:/var/lib/postgresql/data'],
   'healthcheck':{'test':['CMD-SHELL','pg_isready -U keycloak'],'interval':'10s','timeout':'5s','retries':12}},
 'keycloak':{'image':'quay.io/keycloak/keycloak:26.7.3','restart':'unless-stopped',
   'command':['start','--import-realm'],'depends_on':{'postgres':{'condition':'service_healthy'}},
   'ports':['127.0.0.1:8080:8080'],'volumes':['./import:/opt/keycloak/data/import:ro'],
   'environment':{'KC_DB':'postgres','KC_DB_URL':'jdbc:postgresql://postgres:5432/keycloak',
   'KC_DB_USERNAME':'keycloak','KC_DB_PASSWORD':credentials['db_password'],
   'KC_BOOTSTRAP_ADMIN_USERNAME':'pfa-admin','KC_BOOTSTRAP_ADMIN_PASSWORD':credentials['admin_password'],
   'KC_HOSTNAME':f'https://idp.{ip}.sslip.io','KC_HTTP_ENABLED':'true','KC_PROXY_HEADERS':'xforwarded',
   'KC_PROXY_TRUSTED_ADDRESSES':'172.16.0.0/12','KC_HEALTH_ENABLED':'true',
   'KC_LOG_LEVEL':'INFO,org.keycloak.events:debug'},
   'logging':{'driver':'json-file','options':{'max-size':'10m','max-file':'3'}}}},
 'volumes':{'postgres-data':{}}}
(base/'docker-compose.yml').write_text(json.dumps(compose,indent=2))
Path('/opt/pfa-demo/app.env').write_text('\n'.join([
 'APP_SECRET='+credentials['app_secret'],'CLIENT_SECRET='+credentials['client_secret'],
 f'OIDC_ISSUER=https://idp.{ip}.sslip.io/realms/pfa'])+'\n')
Path('/root/pfa-private/restic-password').write_text(credentials['restic_password'])
with Path('/etc/hosts').open('a') as f:
 f.write(f'\n127.0.0.1 idp.{ip}.sslip.io app.{ip}.sslip.io\n')
PY
# The Keycloak container runs unprivileged; only the import JSON must be readable there.
chmod 755 /opt/pfa-identity /opt/pfa-identity/import
chown 1000:1000 /opt/pfa-identity/import/pfa-realm.json
chmod 600 /opt/pfa-identity/import/pfa-realm.json
chmod 600 /opt/pfa-identity/docker-compose.yml /opt/pfa-demo/app.env /root/pfa-private/*
cd /opt/pfa-identity
docker-compose up -d
# Remove import credentials after the first successful realm import (done in verification).
python3 -m venv /opt/pfa-demo/venv
/opt/pfa-demo/venv/bin/pip install 'Flask>=3.1,<4' 'Authlib>=1.6,<2' 'gunicorn>=23,<24' requests
/opt/pfa-demo/venv/bin/pip freeze
chmod -R a+rX /opt/pfa-demo/venv
install -m 644 /home/labadmin/demo-app.py /opt/pfa-demo/app.py
cat >/etc/systemd/system/pfa-app.service <<'EOF'
[Unit]
Description=PFA protected OIDC demonstration application
After=network-online.target
[Service]
User=pfa-app
Group=pfa-app
WorkingDirectory=/opt/pfa-demo
EnvironmentFile=/opt/pfa-demo/app.env
ExecStart=/opt/pfa-demo/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 2 app:app
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log/pfa-app
[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/pfa-app.service
systemctl daemon-reload
systemctl enable --now pfa-app
cat >/etc/caddy/Caddyfile <<EOF
{
  acme_ca https://acme-v02.api.letsencrypt.org/directory
}
idp.$PUBLIC_IP.sslip.io {
  reverse_proxy 127.0.0.1:8080
  header Strict-Transport-Security "max-age=86400"
}
app.$PUBLIC_IP.sslip.io {
  reverse_proxy 127.0.0.1:8000
  header Strict-Transport-Security "max-age=86400"
}
EOF
chmod 644 /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile
systemctl enable --now caddy
systemctl reload caddy
curl --fail --retry 3 -o /tmp/wazuh-key https://packages.wazuh.com/key/GPG-KEY-WAZUH
gpg --dearmor --yes -o /usr/share/keyrings/wazuh.gpg /tmp/wazuh-key
chmod 644 /usr/share/keyrings/wazuh.gpg
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' >/etc/apt/sources.list.d/wazuh.list
chmod 644 /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER=10.0.5.10 WAZUH_AGENT_NAME=pfa-services apt-get install -y wazuh-agent
python3 - <<'PY'
from pathlib import Path
p=Path('/var/ossec/etc/ossec.conf')
t=p.read_text()
extra='''
  <localfile><log_format>json</log_format><location>/var/log/suricata/eve.json</location></localfile>
  <localfile><log_format>json</log_format><location>/var/log/pfa-app/events.json</location></localfile>
'''
t=t.replace('</ossec_config>',extra+'</ossec_config>',1)
t=t.replace('<syscheck>','<syscheck>\n    <directories realtime="yes">/opt/pfa-demo/data</directories>',1)
p.write_text(t)
PY
mkdir -p /etc/suricata/rules
cat >/etc/suricata/rules/pfa.rules <<'EOF'
alert http any any -> any any (msg:"PFA controlled IDS test"; flow:established,to_server; http.uri; content:"/pfa-ids-check"; sid:1000001; rev:1;)
EOF
python3 - <<'PY'
import yaml
from pathlib import Path
p=Path('/etc/suricata/suricata.yaml')
t=yaml.safe_load(p.read_text())
t['default-rule-path']='/etc/suricata/rules'
t['rule-files']=['pfa.rules']
t['vars']['address-groups']['HOME_NET']='[10.0.0.0/16]'
p.write_text('%YAML 1.1\n---\n'+yaml.safe_dump(t,sort_keys=False))
PY
SURICATA_IFACE=$(ip -o -4 route show to default | awk '{print $5;exit}')
sed -i "s/^IFACE=.*/IFACE=$SURICATA_IFACE/" /etc/default/suricata
suricata -T -c /etc/suricata/suricata.yaml
systemctl enable wazuh-agent suricata
systemctl restart wazuh-agent suricata
echo 'PFA synthetic record DEMO-001; no personal data.' >/opt/pfa-demo/data/demo.txt
chmod 644 /opt/pfa-demo/data/demo.txt
export RESTIC_REPOSITORY=/var/backups/pfa-restic
export RESTIC_PASSWORD_FILE=/root/pfa-private/restic-password
restic init
restic backup /opt/pfa-demo/data
restic restore latest --target /var/backups/pfa-restore-test
cmp /opt/pfa-demo/data/demo.txt /var/backups/pfa-restore-test/opt/pfa-demo/data/demo.txt
echo 'Local encrypted backup/restore comparison passed. Same-VM repository is not disaster recovery.'
systemctl is-active pfa-app caddy docker suricata wazuh-agent
echo "COMPLETE SERVICES $(date --iso-8601=seconds) https://app.$PUBLIC_IP.sslip.io"
