import subprocess, re

def run(cmd):
    result = subprocess.run(cmd, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).stdout.decode('utf-8')
    return result

interfaces = run("ip addr show")
bridgesRaw = re.findall("(vmbr[0-9]+):",interfaces, re.MULTILINE | re.DOTALL)
bridges = ""
for index,bridge in enumerate(bridgesRaw):
    bridges += "ifindex="+str(index +1)+"	ifname="+bridge+"\n"
run("echo '"+bridges+"' > /etc/pmacct/interfaces.map")
