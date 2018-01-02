import comodo_api
import configparser
import logging
import jsend

from flask import Flask, jsonify, request
from flask_gssapi import GSSAPI
from flask_restplus import Resource, Api, fields
from logging.handlers import SysLogHandler
from raven.contrib.flask import Sentry

# Enable logging
syslog_handler = SysLogHandler()
syslog_handler.setLevel(logging.WARNING)

app = Flask(__name__)
app.logger.addHandler(syslog_handler)

# If debugging is needed
# app.config['DEBUG'] = True

# Configure the application
# SENTRY_DSN must be defined as an environment variable, if not sentry will simply not function, see here:
# https://docs.sentry.io/clients/python/integrations/flask/
sentry = Sentry(app)

# Pull in the configuration without interpolation for any special password characters
config = configparser.ConfigParser(interpolation=None)

config.read('/etc/comodo_proxy/comodo_proxy.ini')

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


# Load the ACL
try:
    with open('/etc/comodo_proxy/acl', 'r') as f:
        acl_list=[line.rstrip('\n') for line in f]
except IOError:
    app.logger.critical('Unable to open /etc/comodo_proxy/acl')

app.logger.debug('ACL List consumed: %s' % acl_list)

# The following models define the input and output, this mainly aids in documentation for
# OpenAPI/Swagger

# All responses should inherit the status_response_model, this is basically jsend format, see here:
# https://labs.omniti.com/labs/jsend
status_response_model = api.model('Status Response',
                                  {'status': fields.String(description='The Status Message', example='success')})


csr_model = api.model('CSR Model',
                      {'cert_type_name':
                       fields.String(required=True,
                                     description='The full cert type name', example='PlatinumSSL Certificate'),
                       'csr':
                       fields.String(required=True, description='The Certificate Signing Request',
                                     example='-----BEGIN CERTIFICATE REQUEST-----\n[CSR GOES HERE]\n'
                                             '-----END CERTIFICATE REQUEST-----'),
                       'revoke_password':
                       fields.String(required=True, description='A password for certificate revocation',
                                     example='BadPassword'),
                       'server_type':
                       fields.String(required=True,
                                     description='The type of server for the TLS certificate',
                                     example='Apache/ModSSL'),
                       'subject_alt_names':
                       fields.String(required=True,
                                     description='Subject Alternative Names separated by a ",".',
                                     example='1.example.com,2.example.com'),
                       'term': fields.Integer(required=True,
                                              description='The term in years for the certificate', min=1, max=3,
                                              example=3)
                       }
                      )

csr_data_response = api.model('CSR Data Response',
                              {'certificate_id': fields.Integer(description='The Certificate ID', example=1234)},
                             )

csr_response_model = api.inherit('CSR Response Model', status_response_model,
                                 {'data': fields.Nested(csr_data_response)}
                                )

certificate_model = api.model('Certificate Info Model',
                              {'format_type': fields.String(description='Comodo supported format types',
                                                            example='X509 PEM Bundle'),
                              }
                             )

certificate_info_data = api.model('Certificate Info Data Model',
                                  {'formats': fields.List(
                                               fields.String(description='Comodo supported certificate formats',
                                                             example='Apache/ModSSL')),
                                   'format_type': fields.List(
                                                   fields.String(description='Comodo supported format types',
                                                                 example='X509 PEM Bundle')),
                                   'cert_types': fields.List(
                                                   fields.String(
                                                       description='The certificate types supported for the user',
                                                       example='PlatinumSSL Certificate')),
                                  }
                                 )

certificate_info_response_model = api.inherit('Certificate Info Response Model', status_response_model,
                                              {'data': fields.Nested(certificate_info_data)}
                                             )

# The certificate data that is returned in the certificate_response_model
certificate_data_model = api.model('Certificate Data Model',
                                   {'certificate_id': fields.Integer(description='The Certificate ID', example=1234),
                                    'certificate': fields.String(description='The certificate',
                                                                 example='-----BEGIN CERTIFICATE-----\n[CERT HERE]\n'
                                                                         '-----END CERTIFICATE-----\n'),
                                    'certificate_status': fields.String(description='Either pending or issued',
                                                                        example='issued'),
                                    }
                                   )

certificate_response_model = api.inherit('Certificate Response Model', status_response_model,
                                         {'data': fields.Nested(certificate_data_model)}
                                         )

revoke_model = api.model('Revoke Model',
                         {'reason':
                          fields.String(description='Reason for revocation, must not be blank',
                                        example='Key compromise')
                          }
                         )

revoke_response_model = api.inherit('Revoke Response Model', status_response_model)


# Initialize our proxy
comodo = comodo_api.ComodoTLSService(**kwargs)


@api.route('/comodo/v1.0/<int:certificate_id>')
@api.doc(params={'certificate_id': 'The certificate ID'})
@api.response(404, 'Certificate not found')
class ComodoCertificate(Resource):
    @gssapi.require_user(*acl_list)
    @api.doc(body=certificate_model, )
    @api.response(200, 'Certificate', certificate_response_model)
    def get(self, certificate_id, username=''):
        """Request the signed public key by Certificate ID"""

        app.logger.info('User: %s is requesting a completed certificate, ID: %s' % (username, certificate_id))
        body = request.get_json()

        result = comodo.collect(cert_id=certificate_id, format_type=body['format_type'])

        app.logger.debug('User: %s request status: %s' % (username, result['status']))

        if result['status'] == 'success':
            return jsonify(result), 200
        else:
            return jsonify(result), 400

    @gssapi.require_user(*acl_list)
    @api.response(200, 'Successful', revoke_response_model)
    @api.doc(body=revoke_model)
    def delete(self, certificate_id, username=''):
        """Revoke the certificate by Certificate ID"""
        body = request.get_json()

        app.logger.info('User: %s Revoking Certificate ID: %s' % (username, certificate_id))

        result = comodo.revoke(cert_id=certificate_id, reason=body.get('reason', 'Revoked'))

        app.logger.info('User: %s revoking certificate ID: %s, result: %s' %
                        (username, certificate_id, result['status']))

        if result['status'] == 'success':
            return jsonify(result), 200
        else:
            return jsonify(result), 400


@api.route('/comodo/v1.0/tls')
class ComodoTLSRequestCertificate(Resource):
    @gssapi.require_user(*acl_list)
    @api.doc(body=csr_model)
    @api.response(201, 'CSR successfully submitted', csr_response_model)
    def post(self, username=''):
        """Submit a Certificate Signing Request (CSR) for a SSL/TLS certificate"""

        app.logger.info('User: %s is submitting a CSR' % username)

        body = request.get_json()

        app.logger.debug('User: %s CSR: %s' % (username, body['csr']))

        result = comodo.submit(cert_type_name=body['cert_type_name'],
                               csr=body['csr'],
                               revoke_password=body['revoke_password'],
                               server_type=body['server_type'],
                               subject_alt_names=body.get('subject_alt_names', ''),
                               term=body['term'])

        app.logger.info('User: %s Result is: %s' % (username, result['status']))

        if result['status'] == 'success':
            return jsonify(result), 201
        else:
            return jsonify(result), 400

    @gssapi.require_user(*acl_list)
    @api.response(200, 'Certificate information', certificate_info_response_model)
    def get(self, username=''):
        """Retrieve information about the available certificates and server types"""

        app.logger.debug('User: %s get certificate information.' % username)

        formats = sorted(list(comodo.formats.keys()))
        format_type = sorted(list(comodo.format_type.keys()))

        result = comodo.get_cert_types()

        app.logger.debug('User: %s get certificate information, result: %s.' % (username, result['status']))

        if result['status'] == 'success':
            r = jsend.success({'formats': formats, 'format_type': format_type,
                               'cert_types': [x['name'] for x in result['data']['cert_types']]})
            return jsonify(r), 200
        else:
            return jsonify(result), 400


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Development Server Help')
    parser.add_argument("-d", "--debug", action="store_true", dest="debug_mode",
                        help="run in debug mode (for use with PyCharm)", default=False)
    parser.add_argument("-p", "--port", dest="port",
                        help="port of server (default:%(default)s)", type=int, default=5000)

    cmd_args = parser.parse_args()
    app_options['port'] = cmd_args.port
    app_options['host'] = '0.0.0.0'

    if cmd_args.debug_mode:
        app_options['debug'] = True
        app_options['use_debugger'] = False
        app_options['use_reloader'] = True

    app.run(**app_options)
