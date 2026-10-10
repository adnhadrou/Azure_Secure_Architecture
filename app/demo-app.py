"""Small OIDC relying party: authorization is checked on the server."""
import json
import logging
import os
from datetime import datetime, timezone
from urllib.parse import urlencode
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, render_template_string, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ['APP_SECRET']
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE='Lax', PERMANENT_SESSION_LIFETIME=1800)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
issuer = os.environ['OIDC_ISSUER']
oauth = OAuth(app)
oauth.register('keycloak', client_id='pfa-portal', client_secret=os.environ['CLIENT_SECRET'],
               server_metadata_url=issuer+'/.well-known/openid-configuration',
               client_kwargs={'scope':'openid profile email', 'code_challenge_method':'S256'})
audit = logging.getLogger('pfa-audit')
audit.setLevel(logging.INFO)
audit.addHandler(logging.FileHandler(os.environ.get('AUDIT_LOG_PATH', '/var/log/pfa-app/events.json')))

def event(kind, user):
    audit.info(json.dumps({'timestamp':datetime.now(timezone.utc).isoformat(),
                           'pfa_event':kind, 'username':user}))

PAGE = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PFA | Secure application</title><style>
body{font:17px system-ui;background:#101c2c;color:#eef5fb;margin:0;padding:7vw;max-width:1000px}
.kicker{color:#55d4c7;font:700 13px system-ui;letter-spacing:2px}h1{font-size:clamp(30px,6vw,58px);line-height:1.1}
p{color:#b9cada;line-height:1.7}.card{border:1px solid #34485c;padding:24px;border-radius:12px;margin:24px 0;background:#192a3d}
a{display:inline-block;background:#55d4c7;color:#071b24;padding:13px 20px;border-radius:6px;text-decoration:none;font-weight:700}
.facts{display:flex;gap:20px;flex-wrap:wrap}.facts span{border:1px solid #34485c;padding:12px;border-radius:6px}
small{color:#92aabe}</style><div class="kicker">PFA / AZURE SECURITY LAB</div><h1>{{ title }}</h1><p>{{ detail }}</p>
<div class="card">{{ body }}</div><div class="facts"><span>Keycloak identity</span><span>OIDC + PKCE</span><span>Server-side role policy</span></div>
<p><a href="{{ action_url }}">{{ action }}</a></p><small>Temporary student demonstration. Synthetic data only.</small></html>'''

@app.route('/')
def index():
    user = session.get('user')
    if user:
        return redirect('/workspace')
    return render_template_string(PAGE, title='One identity. Controlled access.',
        detail='Sign in through the lab identity provider to access the protected workspace.',
        body='Access requires the lab-user role. New demo users must enroll an authenticator before their first login.',
        action='Sign in with Keycloak', action_url='/login')

@app.route('/login')
def login():
    return oauth.keycloak.authorize_redirect(url_for('callback',_external=True))

@app.route('/callback')
def callback():
    token=oauth.keycloak.authorize_access_token()
    # Authlib validates the ID token signature, issuer, audience, expiry and nonce.
    info=token['userinfo']
    session.clear()
    session['user']={'name':info.get('preferred_username','unknown'),'roles':info.get('roles',[])}
    session['id_token']=token['id_token']
    session.permanent=True
    permitted='lab-user' in session['user']['roles']
    event('login_success' if permitted else 'access_denied',session['user']['name'])
    return redirect('/workspace')

@app.route('/workspace')
def workspace():
    user=session.get('user')
    if not user:
        return redirect('/login')
    if 'lab-user' not in user['roles']:
        return render_template_string(PAGE,title='Access denied',
            detail='Authentication succeeded. Your account does not have the required application role.',
            body=f"User: {user['name']} | Required role: lab-user | HTTP 403",
            action='Sign out',action_url='/logout'),403
    return render_template_string(PAGE,title='Protected workspace',detail='Your identity and application role have been verified.',
        body=f"User: {user['name']} | Role: lab-user | Data: PFA synthetic project record DEMO-001",
        action='Sign out',action_url='/logout')

@app.route('/logout')
def logout():
    id_token=session.get('id_token')
    session.clear()
    parameters={'client_id':'pfa-portal','post_logout_redirect_uri':url_for('index',_external=True)}
    if id_token:
        parameters['id_token_hint']=id_token
    return redirect(issuer+'/protocol/openid-connect/logout?'+urlencode(parameters))

@app.route('/health')
def health():
    return {'status':'ok','service':'pfa-portal'}
