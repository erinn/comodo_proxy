import comodo_api
import configparser
import logging
import pathlib
import jsend

from flask import Flask, jsonify, request
from flask_gssapi import GSSAPI
from flask_migrate import Migrate
from flask_restplus import Resource, Api, fields
from flask_sqlalchemy import SQLAlchemy
from raven.contrib.flask import Sentry



app.config['SQLALCHEMY_DATABASE_URI'] = \
    'mysql://comodo_proxy:echee4yeloa0Iajienu9thahGhoo4x@127.0.0.1:8001/comodo_proxy'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Establish logging when running under gunicorn. If running standalone will function as a normal
# flask server.
if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

app.logger.info('comodo_proxy is starting.')

# Configure the application

# SENTRY_DSN must be defined as an environment variable, if not, sentry will simply not function (which is fine),
# see here: https://docs.sentry.io/clients/python/integrations/flask/
sentry = Sentry(app)

# Pull in the configuration without interpolation for any special password characters
config = configparser.ConfigParser(interpolation=None)

config_file_path = pathlib.Path('/etc/comodo_proxy/comodo_proxy.ini')
try:
    config.read(config_file_path)
except IOError:
    app.logger.critical('Unable to open: %s' % config_file_path)

kwargs = dict(config['default'])

# The value should come through as a bool not str.
kwargs['client_cert_auth'] = config['default'].getboolean('client_cert_auth')

# Set the host principle service name to HTTP by default
app.config['GSSAPI_SERVICE_NAME'] = kwargs.get('gssapi_service_name', 'HTTP')
app.logger.debug('GSSAPI_SERVICE_NAME: %s' % app.config['GSSAPI_SERVICE_NAME'])

# Allow the host name for the principle to be overridden, defaults to FQDN.
if 'gssapi_hostname' in kwargs:
    app.config['GSSAPI_HOSTNAME'] = kwargs['gssapi_hostname']
app.logger.debug('GSSAPI_HOSTNAME: %s' % app.config['GSSAPI_HOSTNAME'])

# We validate all input data
app.config['RESTPLUS_VALIDATE'] = True
# Enable the JSON editor for the swagger UI
app.config.SWAGGER_UI_JSONEDITOR = True


# Initialize the application
api = Api(app)
gssapi = GSSAPI(app)

acl_list = []



# Initialize our proxy



if __name__ == '__main__':
    pass
