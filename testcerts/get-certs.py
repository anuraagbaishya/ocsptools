import subprocess as sub
import shlex
import sys, os
import re
import requests
from urllib.parse import urlparse
def find_between(s, first, last):
    result = []
    while last in s:
        start = s.index(first)
        end = s.index(last)
        result.append(s[start:end+len(last)])
        s = s[end+len(last):]
    return result

def find_errors(error):
    error_string = ""
    flag = 0
    if "self signed certificate" in error:
        flag += 1
        error_string += "self signed\t"
    if "certificate has expired" in error:
        flag += 1
        error_string += "certificate expired\t"
    if "handshake failure" in error:
        flag += 1
        error_string += "handshake failure\t"
    if "Connection refused" in error:
        flag += 1
        error_string += "connection refused\t"
    if "gethostbyname failure" in error or "Name or service not known" in error:
        flag += 1
        error_string += "hostname not found\t" 
    if flag == 0:
        error_string += "errored\t"

    return error_string

def write_to_file(filename, mode, data):

    with open(filename, mode) as f:
        f.write(data)
        f.close() 

def openssl_call(domain):
    cmd = "timeout 10 openssl s_client -showcerts -connect " + domain +":443 -servername" + domain
    cmdarg = shlex.split(cmd)
    p = sub.Popen(cmdarg,stdin =sub.PIPE, stdout=sub.PIPE,stderr=sub.PIPE)
    output, errors = (p.communicate())
    return (output, errors)

def check_certs(url, output, errors):

    if output.decode('utf-8') != "":
        certs = (find_between(output.decode('utf-8'), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"))
        #certs = re.search(r'-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----',output.decode('utf-8')) TODO Optional way to do it
        #print("Cert from {0}:\n {1}".format(d, certs)) 
        if len(certs) < 2:
            error = find_errors(errors.decode('utf-8'))
            if error == "errored\t" and len(certs) == 1:
                error = "Chain certificate not provided"
            print("..." + error)
            write_to_file("errors.txt", "a+", url + ":" + error + "\n")
            return (None, None)
        else:
            print("...done")
            cert = certs[0]
            cert_chain = certs[1:]
            return (cert, cert_chain)

    elif errors.decode('utf-8') != "":

        error = find_errors(errors.decode('utf-8'))
        print("..." + error)
        write_to_file("errors.txt", "a+", url + ":" + error+ "\n")
        return (None, None)

    elif output.decode('utf-8') == "":
        error = "timed out"
        print("...timed out")
        write_to_file("errors.txt", "a+", url + ":" + error+ "\n")
        return (None, None)    

    return (cert, cert_chain)    

def main(domain_file):
    output, errors = b"", b""
    try:
        with open(domain_file, "r") as f:
            domains = f.readlines()
        for d in domains:
            d = d.replace("\n", "")
            filename = d + ".pem"
            filename_chain = d + "-chain.pem"
            print("Retrieving certificate from {}...".format(d), end='')
            
            out = openssl_call(d)
            output = out[0]
            errors = out[1]

            error = find_errors(errors.decode('utf-8'))
            
            if error == "handshake failure":
                print ("...redirecting")
                try:
                    r = requests.get("https://"+d)
                    d = urlparse(r.url).hostname
                    out = openssl_call(d)
                    output = out[0]
                    errors = out[1]
                except:
                    pass

            cert_data = check_certs(d, output, errors)

            if cert_data[0] is not None:

                with open (os.path.join("cert", filename), "w+") as f:
                    f.write(cert_data[0])
                    f.close()
                with open (os.path.join("chain", filename_chain), "w+") as f:
                    for c in cert_data[1]:
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

