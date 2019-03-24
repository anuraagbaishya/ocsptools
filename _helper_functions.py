from asn1crypto import core, x509, pem, ocsp, algos
import os
from urllib import request

def return_cert_from_file(filename):
	with open(filename, 'rb') as f:
		der_bytes = f.read()
		if pem.detect(der_bytes):
			type_name, headers, der_bytes = pem.unarmor(der_bytes)
			return x509.Certificate.load(der_bytes)
		else:
			raise ValueError ("{} doesn't contain DER data".format(filename))

def return_ocsp_request_object(cert, issuer, algo, nonce=True):
	cert_details = ocsp.CertId({
		'issuer_name_hash': getattr(cert.issuer, algo),
		'issuer_key_hash': getattr(issuer.public_key, algo),
		'hash_algorithm': algos.DigestAlgorithm({'algorithm': algo}),
		'serial_number': cert.serial_number,
	})	

	request_obj = ocsp.Request({
		'req_cert': cert_details,
	})

	tbs_request_obj = ocsp.TBSRequest({
		'request_list': ocsp.Requests([request_obj])
	})

	if nonce:
		nonce_extension = ocsp.TBSRequestExtension({
			'extn_id': 'nonce',
			'critical': True,
			'extn_value': core.OctetString(os.urandom(16)),
		})
		tbs_request_obj['request_extensions']: ocsp.TBSRequestExtensions([nonce_extension])

	ocsp_request_obj = ocsp.OCSPRequest({
		'tbs_request': tbs_request_obj,
	})	

	return ocsp_request_obj

def make_ocsp_request(ocsp_url, ocsp_request_obj, timeout=20):
	headers = {
		'Content-Type': 'application/ocsp_request',
		'Accept': 'application/ocsp-response'
	}
	ocsp_request = request.Request(ocsp_url, headers=headers)
	ocsp_response = request.urlopen(ocsp_request, ocsp_request_obj.dump(), timeout)
	ocsp_response_obj = ocsp.OCSPResponse.load(ocsp_response.read())
	return ocsp_response_obj
