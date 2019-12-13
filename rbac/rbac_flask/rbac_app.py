from app import create_app
import os, ssl

basedir = os.path.abspath(os.path.dirname(__file__))

# SSL context
#context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
#context.verify_mode = ssl.CERT_NONE
#context.load_verify_locations('{}\\app\certs'.format(basedir))
#context.verify_flags = ssl.VERIFY_DEFAULT
#context.load_cert_chain('{}\\app\certs\cert.pem'.format(basedir), '{}\\app\certs\key.pem'.format(basedir))

app=create_app()

#app.run(ssl_context=context)
app.run(host='0.0.0.0', port='8090')