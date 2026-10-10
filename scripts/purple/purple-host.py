"""Bounded lab control tests; no exploit, credential reading or external target."""
import datetime, json, pathlib, re, socket, subprocess, sys, time
run=sys.argv[1]
assert re.fullmatch(r'[a-f0-9]{12}',run)
results=[]
for port in [22,443,1514,1515,5601,9200]:
    try:
        with socket.create_connection(('10.0.5.10',port),timeout=2): reachable=True
    except OSError:
        reachable=False
    results.append({'test':'bounded_discovery','target':'10.0.5.10','port':port,
                    'reachable':reachable,'expected_reachable':port in (1514,1515)})
p=pathlib.Path('/opt/pfa-demo/data/purple-'+run+'.txt')
p.write_text('Synthetic purple-team canary. Run '+run+'\n')
time.sleep(5)
p.write_text(p.read_text()+'Controlled modification; no production data.\n')
results.append({'test':'file_tamper','path':str(p),'action':'created_then_modified'})
attempt=subprocess.run(['runuser','-u','pfa-app','--','sudo','-n','/usr/bin/id'],capture_output=True,text=True)
results.append({'test':'privilege_boundary','principal':'pfa-app','command':'sudo -n /usr/bin/id',
                'exit':attempt.returncode,'stdout':attempt.stdout.strip(),'stderr':attempt.stderr.strip(),
                'denied':attempt.returncode != 0})
print(json.dumps({'run_id':run,'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),'results':results},indent=2))
