import subprocess as sub
import shlex
import os

def find_between(s, first, last):
	result = []
	while last in s:
		start = s.index(first)
		end = s.index(last)
		result.append(s[start:end+len(last)])
		s = s[end+len(last):]
	return result

with open("test", "r") as f:
	domains = f.readlines() 	

for d in domains:

	d = d.replace("\n", "")
	cmd = "openssl s_client -showcerts -connect " + d +":443"
	cmdarg = shlex.split(cmd)
	p = sub.Popen(cmdarg,stdin =sub.PIPE, stdout=sub.PIPE,stderr=sub.PIPE)
	output, errors = (p.communicate())
	certs = (find_between(output.decode('utf-8'), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"))

	cert = certs[0]
	cert_chain = certs[1:]
	filename = d + ".pem"
	filename_chain = d + "-chain.pem" 
	with open (os.path.join("cert", filename), "w+") as f:
		f.write(cert)
		f.close()
	with open (os.path.join("chain", filename_chain), "w+") as f:
		for c in cert_chain:
			f.write(c)