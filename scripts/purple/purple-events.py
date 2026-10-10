"""Collect fresh, selected evidence fields, excluding credentials and raw logs."""
import collections, datetime, json, pathlib, re, sys
run,start,source=sys.argv[1:4]
assert re.fullmatch(r'[a-f0-9]{12}',run)
def parse_time(value):
    value=value.replace('Z','+00:00')
    value=re.sub(r'(\.\d{6})\d+',r'\1',value)
    value=re.sub(r'([+-]\d{2})(\d{2})$',r'\1:\2',value)
    return datetime.datetime.fromisoformat(value)
start=parse_time(start)
path=pathlib.Path('/var/log/suricata/eve.json' if source=='suricata' else '/var/ossec/logs/alerts/alerts.json')
events=[]
with path.open() as f:
    for line in collections.deque(f,maxlen=100000):
        try:
            a=json.loads(line)
            stamp=parse_time(a['timestamp'])
        except (ValueError,KeyError): continue
        if stamp<start: continue
        data=a if source=='suricata' else a.get('data',{})
        alert=data.get('alert',{})
        full=a.get('full_log','')
        file=a.get('syscheck',{}).get('path','')
        url=data.get('http',{}).get('url','')
        kind=None
        if run in url and str(alert.get('signature_id'))=='1000003': kind='web_probe'
        elif run in file: kind='file_integrity'
        elif 'pt-'+run in full: kind='invalid_ssh_user'
        elif 'sudo' in full and 'pfa-app' in full:
            kind='controller_admin_action' if str(a.get('rule',{}).get('id'))=='5402' else 'privilege_boundary'
        if not kind: continue
        events.append({'timestamp':a['timestamp'],'kind':kind,'source':source,
                       'rule':a.get('rule',{}).get('id'),'level':a.get('rule',{}).get('level'),
                       'description':a.get('rule',{}).get('description'),
                       'agent':a.get('agent',{}).get('name'),'signature_id':alert.get('signature_id'),
                       'action':alert.get('action'),'url':url,'file':file})
print(json.dumps({'run_id':run,'since':start.isoformat(),'events':events},indent=2))
