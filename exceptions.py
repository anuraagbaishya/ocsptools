class OCSPNonceMismatchError(Exception):
	pass
class OCSPMalformedRequestError(Exception):
	pass
class NotBasicOCSPResponseError(Exception):
	pass
class OCSPStatusFailedError(Exception):
	pass
class OCSPSerialMismatchError(Exception):
	pass

class OCSPIssuerKeyMismatchError(Exception):
	pass

class OCSPIssuerNameMismatchError(Exception):
	pass

class OCSPThisUpdateTimeError(Exception):
	pass

class OCSPNextUpdateTimeError(Exception):
	pass