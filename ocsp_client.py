from asn1crypto import core, ocsp, x509, algos, pem
import sys
import _helper_functions as hf
from urllib import request
import os

class OCSPValidationError(Exception):

    pass

def get_ocsp_response(cert_file, issuer_file, algo='sha1', nonce=True, timeout=20):
	try:
		cert = hf.return_cert_from_file(cert_file)
	except ValueError:
		raise TypeError("{} is not a valid x509 certificate".format(cert_file))
	try:
		issuer = hf.return_cert_from_file(issuer_file)
	except ValueError:
		raise TypeError("{} is not a valid x509 certificate".format(issuer_file))

	if algo not in ('sha1', 'sha256'):
		raise ValueError("{} is not either of sha1 or sha256".format(algo))

	if not isinstance(nonce, bool):
		raise TypeError("{} is not a boolean value for nonce".format(nonce))

	ocsp_request_obj = hf.return_ocsp_request_object(cert, issuer, algo, nonce)

	headers = {
		'Content-Type': 'application/ocsp_request',
		'Accept': 'application/ocsp-response'
	}
	for ocsp_url in cert.ocsp_urls:
		try:
			ocsp_request = request.Request(ocsp_url, headers=headers)
			ocsp_response = request.urlopen(ocsp_request, ocsp_request_obj.dump(), timeout)
			ocsp_response_obj = ocsp.OCSPResponse.load(ocsp_response.read())
			request_nonce = ocsp_request_obj.nonce_value
			response_nonce = ocsp_response_obj.nonce_value
			if request_nonce and response_nonce and request_nonce.native != response_nonce.native:
				raise OCSPValidationError('Unable to verify OCSP response since the request and response nonces do not match')
			
			print (ocsp_response_obj['response_status'].native)
		except Exception as e:
			print (e)

get_ocsp_response(sys.argv[1], sys.argv[2], 'sha256', True)
