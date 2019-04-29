from flask import Flask, render_template, request
from ocsp_validator import get_ocsp_response, validate_ocsp_response
from datetime import datetime, timezone
from werkzeug import secure_filename
import _helper_functions as hf
import json
import os

cwd = os.getcwd()
app = Flask(__name__, instance_path=cwd+'/uploads', static_url_path='/static')

os.makedirs(os.path.join(app.instance_path, 'cert'), exist_ok=True)
os.makedirs(os.path.join(app.instance_path, 'chain'), exist_ok=True)

@app.route('/', methods=['GET','POST'])
def home():
	return render_template('index.html')

@app.route('/response', methods=['GET','POST'])
def response():
	return render_template('response.html')

@app.route('/response-check', methods=['GET','POST'])
def response_check():
	response_string = ""
	if request.method == 'POST':
		check = request.form.get('action')
		if check == "Check OCSP Response":
			cert_file = request.files['cert-file']
			cert_file.save(os.path.join(app.instance_path, 'cert', secure_filename(cert_file.filename)))

			issuer_file = request.files['issuer-file']
			issuer_file.save(os.path.join(app.instance_path, 'chain', secure_filename(issuer_file.filename)))

			try:
				cert = hf.return_cert_from_file(os.path.join(app.instance_path, 'cert', secure_filename(cert_file.filename)))
			except ValueError:
				return "{} is not a valid x509 certificate".format(cert_file.filename)

			try:
				issuer = hf.return_cert_from_file(os.path.join(app.instance_path, 'chain', secure_filename(issuer_file.filename)))
			except ValueError:
				return "{} is not a valid x509 certificate".format(issuer_file.filename)

			current_time = datetime.now(timezone.utc)	
			response = get_ocsp_response(cert, issuer, 'sha256', True)
			ocsp_request = response[0]
			ocsp_responses = response[1]

			lints_list = validate_ocsp_response(cert, issuer, ocsp_request, ocsp_responses, current_time)
			return json.dumps(lints_list[0])

if __name__ == "__main__":
	app.run(debug=True,host='0.0.0.0', port=4000)