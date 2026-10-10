"""Toggle only the controlled purple exercise signature, preserving existing IPS rules."""
import pathlib, subprocess, sys
mode=sys.argv[1]
assert mode in ('alert','drop')
p=pathlib.Path('/etc/suricata/rules/pfa-ips.rules')
original=p.read_text()
lines=[line for line in original.splitlines() if 'sid:1000003;' not in line]
lines.append(mode+' http any any -> any any (msg:"PFA purple controlled web probe"; flow:established,to_server; http.uri; content:"/pfa-purple-probe"; startswith; sid:1000003; rev:1;)')
p.write_text('\n'.join(lines)+'\n')
try:
    subprocess.run(['suricata','-T','-c','/etc/suricata/pfa-ips.yaml','-q','0'],check=True)
except Exception:
    p.write_text(original)
    raise
subprocess.run(['systemctl','restart','suricata'],check=True)
subprocess.run(['systemctl','is-active','suricata'],check=True)
print('Purple SID 1000003 mode: '+mode+'; existing SID 1000002 retained.')
