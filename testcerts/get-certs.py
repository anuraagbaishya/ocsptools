import subprocess as sub
import shlex
import sys, os
import re

def find_between(s, first, last):
    result = []
    while last in s:
        start = s.index(first)
        end = s.index(last)
        result.append(s[start:end+len(last)])
        s = s[end+len(last):]
    return result

def main(domain_file):
#TODO Add timeout functionality
    try:
        with open(domain_file, "r") as f:
            domains = f.readlines()
        for d in domains:
            d = d.replace("\n", "")
            print("Retrieving certificate from {}...".format(d), end='')
            cmd = "openssl s_client -showcerts -connect " + d +":443"
            cmdarg = shlex.split(cmd)
            p = sub.Popen(cmdarg,stdin =sub.PIPE, stdout=sub.PIPE,stderr=sub.PIPE)
            output, errors = (p.communicate())
            certs = (find_between(output.decode('utf-8'), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"))
            #certs = re.search(r'-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----',output.decode('utf-8')) TODO Optional way to do it
            #print("Cert from {0}:\n {1}".format(d, certs))
            if len(certs) == 0:
                cert = "NOT FOUND"
                cert_chain = ["NOT FOUND"]
                print("...failed") 
            else:
                print("...done")
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
                f.close()
    except (OSError, IOError) as e:
        print("Error in opening file {}".format(domain_file))
        print(e)

if __name__ == '__main__':
#TODO Add clean up functionality
#TODO Add supress output functionality
    if len(sys.argv) < 2:
        print("Please provide a file with domain names.")
        exit(1)

    infile = sys.argv[1]
    main(infile)

