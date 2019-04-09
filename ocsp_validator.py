import sys
import _helper_functions as hf
from datetime import datetime, timezone
from certvalidator.registry import CertificateRegistry
from oscrypto import asymmetric
import json
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

    errors ={}
    for ocsp_response_obj in ocsp_response_objs:
        if (ocsp_response_obj['response_status'].native == 'malformed_request'):
            errors['ResponseFailure'] = 'Failed to query OCSP responder'
            return json.dumps(errors)

        request_nonce = ocsp_request_obj.nonce_value
        response_nonce = ocsp_response_obj.nonce_value
        if request_nonce and response_nonce and request_nonce.native != response_nonce.native:
            errors['NonceVerificationFailure'] = 'Unable to verify OCSP response since the request and response nonces do not match'

        if ocsp_response_obj['response_status'].native != 'successful':
            errors['OCSPCheckFailure'] = 'OCSP check returned as failed'

        response_bytes = ocsp_response_obj['response_bytes']
        if response_bytes['response_type'].native != 'basic_ocsp_response':
            errors['ResponseTypeFailure'] = 'OCSP response is not Basic OCSP Response'

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
            errors['CertificateSerialMismatchFailure'] = \
            'OCSP response certificate serial number does not match request certificate serial number'

        if certificate_issuer_key_hash != certificate_issuer_key_hash_from_file:
            errors['IssuerKeyMismatchFailure'] = 'OCSP response issuer key hash does not match request certificate issuer key hash'

        if certificate_issuer_name_hash != certificate_issuer_name_hash_from_file:
            errors['IssuerNameHashMismatchFailure'] = \
                'OCSP response issuer name hash does not match request certificate issuer name hash'

        this_update_time = certificate_response['this_update'].native
        if current_time < this_update_time:
            errors['ThisUpdateTimeError'] = 'OCSP reponse update time is from the future'

        next_update_time = certificate_response['next_update'].native
        if current_time > next_update_time:
            errors['NextUpdateTimeFailure'] = 'OCSP reponse next update time is in the past'
    
        registry = CertificateRegistry(trust_roots=[issuer])

        if tbs_response['responder_id'].name == 'by_key':
            key_identifier = tbs_response['responder_id'].native
            signing_cert = registry.retrieve_by_key_identifier(key_identifier)
            if signing_cert is None:
                errors['SigningCetificateNotFoundFailure'] = 'OCSP response signing certificate not found'
                return json.dumps(errors)
        # if not registry.is_ca(signing_cert):
        #   signing_cert_paths = certificate_registry.build_paths(signing_cert)
        #   for signing_cert_path in signing_cert_paths:
        #       try:
        #           # Store the original revocation check value
        #           changed_revocation_flags = False

        #           skip_ocsp = False if signing_cert.ocsp_no_check_value is not None else True
        #           skip_ocsp = True if signing_cert_path == path else False

            #TODO: Understand this code!
            #       if skip_ocsp and validation_context._skip_revocation_checks is False:
            #           changed_revocation_flags = True

            #           original_revocation_mode = validation_context.revocation_mode
            #           new_revocation_mode = "soft-fail" if original_revocation_mode == "soft-fail" else "hard-fail"

            #           validation_context._skip_revocation_checks = True
            #           validation_context._revocation_mode = new_revocation_mode

            #       if end_entity_name_override is None and signing_cert.sha256 != issuer.sha256:
            #           end_entity_name_override = cert_description + ' OCSP responder'
            #       _validate_path(
            #           validation_context,
            #           signing_cert_path,
            #           end_entity_name_override=end_entity_name_override
            #       )
            #       signing_cert_issuer = signing_cert_path.find_issuer(signing_cert)
            #       break

            #   except (PathValidationError):
            #       continue

            #   finally:
            #       if changed_revocation_flags:
            #           validation_context._skip_revocation_checks = False
            #           validation_context._revocation_mode = original_revocation_mode

            # else:
            #   failures.update((
            #       pretty_message(
            #           '''
            #           Unable to verify OCSP response since response signing
            #           certificate could not be validated
            #           '''
            #       ),
            #       ocsp_response
            #   ))
            #   continue   

        if issuer.issuer_serial != signing_cert.issuer_serial:
            if signing_cert_issuer.issuer_serial != issuer.issuer_serial:
                errors['UnauthorizedSigningCertificateFailure'] = 'OCSP response signed by unauthorized certificate'

            extended_key_usage = signing_cert.extended_key_usage_value
            if 'ocsp_signing' not in extended_key_usage.native:
                errors['ExtendedKeyUsageExtensionValueFailure'] = \
                    'OCSP response signing certificate is not the issuing certificate and it does not have value "ocsp_signing"\
                    for the extended key usage extension'           


        sig_algo = parsed_response['signature_algorithm'].signature_algo
        hash_algo = parsed_response['signature_algorithm'].hash_algo
        try:
            check_cert = asymmetric.load_certificate(signing_cert)
            if sig_algo == 'rsassa_pkcs1v15':
                asymmetric.rsa_pkcs1v15_verify(check_cert, parsed_response['signature'].native, tbs_response.dump(), hash_algo)
            elif sig_algo == 'dsa':
                asymmetric.dsa_verify(check_cert, parsed_response['signature'].native, tbs_response.dump(), hash_algo)
            elif sig_algo == 'ecdsa':
                asymmetric.ecdsa_verify(check_cert, parsed_response['signature'].native, tbs_response.dump(), hash_algo)
            else:
                errors['UnsupportedAlgorithmFailure'] = 'OCSP response signature uses unsupported algorithm'

        except(oscrypto.errors.SignatureError):
            errors['SignatureVerificationFailure'] = 'OCSP response signature could not be verified'

        if certificate_response['cert_status'].name == 'revoked':
            revocation_data = certificate_response['cert_status'].chosen
            if revocation_data['revocation_reason'].native is None:
                errors['CertificateValidityFailure'] = 'Certificate revoked due to unknown reason'
            else:
                errors['CertificateValidityFailure'] = 'Certicate revoked due to ' + revocation_data['revocation_reason'].human_friendly

        if len(errors) == 0:
            errors['NoFailure'] = 'No errors in OCSP response'

        return json.dumps(errors)

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
  print (errors)



