import os
import pathlib
import socket

basedir = pathlib.Path.cwd()


class Config(object):
    COMODO_API_URL = os.environ.get('COMODO_API_URL') or 'https://hard.cert-manager.com/private/ws/EPKIManagerSSL?wsdl'
    COMODO_CERT_TYPE_NAME = os.environ.get('COMODO_CERT_TYPE_NAME') or 'Comodo Unified Communications Certificate'
    # Map string to a boolean, if no value is set, default is False
    COMODO_CLIENT_CERT_AUTH = os.environ.get('COMODO_CLIENT_CERT_AUTH') in ['True', 'true', '1']
    # Path to the public ccertificate
    COMODO_CLIENT_PUBLIC_CERT = os.environ.get('COMODO_CLIENT_PUBLIC_CERT') or ''
    # Path to the private key
    COMODO_CLIENT_PRIVATE_KEY = os.environ.get('COMODO_CLIENT_PRIVATE_KEY') or ''
    COMODO_CUSTOMER_LOGIN_URI = os.environ.get('COMODO_CUSTOMER_LOGIN_URI') or ''
    COMODO_LOGIN = os.environ.get('COMODO_LOGIN') or ''
    COMODO_ORG_ID = os.environ.get('COMODO_ORG_ID') or ''
    COMODO_PASSWORD = os.environ.get('COMODO_PASSWORD') or ''
    COMODO_REVOKE_PASSWORD = os.environ.get('COMODO_REVOKE_PASSWORD') or ''
    COMODO_SECRET_KEY = os.environ.get('COMODO_SECRET_KEY') or ''

    GSSAPI_HOSTNAME = os.environ.get('GSSAPI_HOSTNAME') or socket.gethostname()
    GSSAPI_SERVICE_NAME = os.environ.get('GSSAPI_SERVICE_NAME') or 'HTTP'

    # We validate all input data
    RESTPLUS_VALIDATE = True

    # The secret key for flask operations
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'eicacheeH9viphuju5ievohshohKoh'

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + (basedir.as_posix() + '/app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Enable the JSON editor for the swagger UI
    SWAGGER_UI_JSONEDITOR = True