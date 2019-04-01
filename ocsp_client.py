import sys
import _helper_functions as hf
from datetime import datetime, timezone

def get_ocsp_response(cert, issuer, algo='sha1', nonce=True, timeout=20):

	if algo not in ('sha1', 'sha256'):
		raise ValueError("{} is not either of sha1 or sha256".format(algo))

	if not isinstance(nonce, bool):
		raise TypeError("{} is not a boolean value for nonce".format(nonce))

	if not isinstance(timeout, int):
		raise TypeError("{} is not an integer value for timeout".format(timeout))

	ocsp_request_obj = hf.return_ocsp_request_object(cert, issuer, algo, nonce)

	ocsp_response_objs = []
	for i in range(len(cert.ocsp_urls)):
		try:		
			ocsp_response_obj = hf.make_ocsp_request(cert.ocsp_urls[i], ocsp_request_obj, timeout)
			ocsp_response_objs.append(ocsp_response_obj)
		except Exception as e:
			print (e)

	return (ocsp_request_obj, ocsp_response_objs)

def validate_ocsp_response(cert, issuer, ocsp_request_obj, ocsp_response_objs, current_time):

	errors = []
	for ocsp_response_obj in ocsp_response_objs:
		if (ocsp_response_obj['response_status'].native == 'malformed_request'):
			errors.append('Failed to query OCSP responder')
			return errors
		request_nonce = ocsp_request_obj.nonce_value
		response_nonce = ocsp_response_obj.nonce_value
		if request_nonce and response_nonce and request_nonce.native != response_nonce.native:
			errors.append('Unable to verify OCSP response since the request and response nonces do not match')

		if ocsp_response_obj['response_status'].native != 'successful':
			errors.append('OCSP check returned as failed')
			
		response_bytes = ocsp_response_obj['response_bytes']
		if response_bytes['response_type'].native != 'basic_ocsp_response':
			errors.append('Response is {}. Must be Basic OCSP Response'.format(response_bytes['response_type'].native))

		parsed_response = response_bytes['response'].parsed
		tbs_response = parsed_response['tbs_response_data']
		certificate_response = tbs_response['responses'][0]
		
		certificate_id = certificate_response['cert_id']
		algo = certificate_id['hash_algorithm']['algorithm'].native

		certificate_issuer_name_hash = certificate_id['issuer_name_hash'].native
		certificate_issuer_key_hash = certificate_id['issuer_key_hash'].native
		certificate_serial_number = certificate_id['serial_number'].native
		
		certificate_issuer_name_hash_from_file = getattr(cert.issuer, algo)
		certificate_issuer_key_hash_from_file = getattr(issuer.public_key, algo)
		certificate_serial_number_from_file = cert.serial_number

		if certificate_serial_number != certificate_serial_number_from_file:
			errors.append('OCSP response certificate serial number does not match request certificate serial number')

		if certificate_issuer_key_hash != certificate_issuer_key_hash_from_file:
			errors.append('OCSP response issuer key hash does not match request certificate issuer key hash')

		if certificate_issuer_name_hash != certificate_issuer_name_hash_from_file:
			errors.append('OCSP response issuer name hash does not match request certificate issuer name hash') 

		this_update_time = certificate_response['this_update'].native
		if current_time < this_update_time:
			errors.append('OCSP reponse update time is from the future')

		next_update_time = certificate_response['next_update'].native
		if current_time > next_update_time:
			errors.append('OCSP reponse next update time is in the past')

		return errors
	
if __name__ == '__main__':

	cert_file = sys.argv[1]
	issuer_file = sys.argv[2]
	try:
		cert = hf.return_cert_from_file(cert_file)
	except ValueError:
		raise TypeError("{} is not a valid x509 certificate".format(cert_file))
	try:
		issuer = hf.return_cert_from_file(issuer_file)
	except ValueError:
		raise TypeError("{} is not a valid x509 certificate".format(issuer_file))

	current_time = datetime.now(timezone.utc)	
	response = get_ocsp_response(cert, issuer, 'sha256', True)
	ocsp_request = response[0]
	ocsp_responses = response[1]
	errors = validate_ocsp_response(cert, issuer, ocsp_request, ocsp_responses, current_time)

	print ("Total Errors: "+str(len(errors)))

	for error in errors:
		print (error)



