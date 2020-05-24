import jsend

from app.api_models import *
from app import api, app, comodo, gssapi
from app.db_queries import add_certificate, certificate_exists
from flask import g, jsonify, request
from flask_restplus import Resource
from app.cert import get_sha256_hash


def user_authorized(username):

    if username.upper() in g.acl_list:
        app.logger.info('User: %s is authorized!', username)
        return True
    else:
        app.logger.info('User: %s is denied!', username)
        return False


@api.route('/comodo/v1.0/<int:certificate_id>')
@api.route('/comodo/v1.0/tls/collect/<int:certificate_id>')
@api.doc(params={'certificate_id': 'The certificate ID'})
@api.response(404, 'Certificate not found')
@api.response(403, 'Unauthorized', unauthorized_response)
class ComodoTLSCertificate(Resource):
    @api.doc(body=certificate_model, )
    @api.response(200, 'Certificate', cert_collect_response)
    @gssapi.require_auth()
    def get(self, certificate_id, username=''):
        """Request the signed public key by Certificate ID"""

        if user_authorized(username):

            app.logger.info('User: %s is requesting a completed certificate, ID: %s' % (username, certificate_id))
            body = request.get_json()

            result = comodo.collect(cert_id=certificate_id, format_type=body['format_type'])

            app.logger.info('User: %s request status: %s' % (username, result['status']))

            if jsend.is_success(result):

                # If the certificate is issued we insert it into the DB
                if result['data']['certificate_status'] == 'issued':

                    # Pull out the actual certificate in PEM format
                    pem = result['data']['certificate']

                    # Get the hash of the certificate
                    hash = get_sha256_hash(pem)

                    # If the certificate isn't already in the DB we add it
                    if not certificate_exists(username, hash):

                        r = add_certificate(certificate_id, hash, pem, username)

                        # We have an error
                        if r:
                            return jsonify(r), 500

                return jsonify(result), 200
            else:
                return jsonify(result), 400
        else:
            r = jsend.fail({'message': 'unauthorized'})
            return jsonify(r), 403


@api.route('/comodo/v1.0/tls/revoke/<int:certificate_id>')
@api.response(403, 'Unauthorized', unauthorized_response)
class ComodoTLSCertificateRevoke(Resource):
    @api.response(200, 'Successful', revoke_response)
    @api.doc(body=revoke_model)
    @gssapi.require_auth()
    def delete(self, certificate_id, username=''):
        """Revoke the certificate by Certificate ID"""

        if user_authorized(username):

            body = request.get_json()

            app.logger.info('User: %s Revoking Certificate ID: %s' % (username, certificate_id))

            result = comodo.revoke(cert_id=certificate_id, reason=body.get('reason', 'Revoked'))

            app.logger.info('User: %s revoking certificate ID: %s, result: %s' %
                            (username, certificate_id, result['status']))

            if jsend.is_success(result):
                return jsonify(result), 200
            else:
                return jsonify(result), 400
        else:
            r = jsend.fail({'message': 'unauthorized'})
            return jsonify(r), 403


@api.route('/comodo/v1.0/tls')
@api.route('/comodo/v1.0/tls/enroll')
@api.response(403, 'Unauthorized', unauthorized_response)
class ComodoTLSCertificateEnroll(Resource):
    @api.doc(body=csr_model)
    @api.response(201, 'CSR successfully submitted', csr_response_model)
    @gssapi.require_auth()
    def post(self, username=''):
        """Submit a Certificate Signing Request (CSR) for a SSL/TLS certificate"""
        if user_authorized(username):

            app.logger.info('User: %s is submitting a CSR' % username)

            body = request.get_json()

            app.logger.debug('User: %s CSR: %s, Subject Alt Names: %s, Term: %s,' %
                             (username, body['csr'], body['subject_alt_names'], body['term']))

            result = comodo.submit(cert_type_name=body['cert_type_name'],
                                   csr=body['csr'],
                                   subject_alt_names=body.get('subject_alt_names', ''),
                                   term=body['term'])

            if jsend.is_success(result):
                app.logger.info('User: %s Result is: %s, Data: %s', username, result['status'], result['data'])
                return jsonify(result), 201
            elif jsend.is_fail(result):
                app.logger.info('User: %s, Result is: %s, Data: %s', username, result['status'], result['data'])
                return jsonify(result), 400
            else:
                app.logger.info('User: %s Result is: %s, Message: %s', username, result['status'], result['message'])
                return jsonify(result), 400
        else:
            r = jsend.fail({'message': 'unauthorized'})
            return jsonify(r), 403

    @api.response(200, 'Certificate information', certificate_info_response_model)
    @gssapi.require_auth()
    def get(self, username=''):
        """Retrieve information about the available certificates and server types"""

        if user_authorized(username):

            app.logger.info('User: %s GET general certificate information.' % username)

            formats = sorted(list(comodo.formats.keys()))
            format_type = sorted(comodo.format_type)

            result = comodo.get_cert_types()

            app.logger.info('User: %s GET certificate information, result: %s.' % (username, result['status']))

            if jsend.is_success(result):
                r = jsend.success({'formats': formats, 'format_type': format_type,
                                   'cert_types': result['data']['types']})
                return jsonify(r), 200
            else:
                return jsonify(result), 400

        else:
            r = jsend.fail({'message': 'unauthorized'})
            return jsonify(r), 403


@api.route('/comodo/v1.0/tls/info/sha256/<string:hash>')
@api.doc(params={'hash': "The certificate's SHA256 hash"})
@api.response(404, 'Certificate not found')
@api.response(403, 'Unauthorized', unauthorized_response)
class ComodoTLSCertificateInfo(Resource):
    """Request certificate information keying on the SHA256 hash of the certificate"""

    @gssapi.require_auth()
    def get(self, hash, username=''):
        """Retrieve the certificate details"""

        if user_authorized(username):
            app.logger.info('User: %s, GET certificate information on hash: %s' % (username, hash))

            cert = certificate_exists(username, hash)

            # The certificate exists, return the information
            if cert:
                app.logger.info('User: %s, certificate found, ID: %s' % (username, cert.id))
                r = jsend.success({'certificate_id': cert.id, 'cert_fqdn': cert.cert_fqdn})
                return jsonify(r), 200
            else:
                app.logger.info('User: %s, certificate NOT found.' % username)
                r = jsend.fail({'message': 'Certificate does not exist for principle {}'.format(username)})
                return jsonify(r), 404
        else:
            r = jsend.fail({'message': 'unauthorized'})
            return jsonify(r), 403


@api.route('/comodo/v1.0/tls/renew/<int:certificate_id>')
@api.doc(params={'certificate_id': 'The Certificate ID'})
@api.response(404, 'Certificate not found')
@api.response(403, 'Unauthorized', unauthorized_response)
class ComodoTLSCertificateRenew(Resource):
    @api.response(201, 'Certificate', cert_renew_response)
    @gssapi.require_auth()
    def post(self, certificate_id, username=''):
        """Submit a Certificate Renewal for a SSL/TLS certificate"""

        if user_authorized(username):

            app.logger.info('User: %s is submitting a renewal for certificate ID: %s' % (username, certificate_id))

            result = comodo.renew(certificate_id)

            app.logger.info('User: %s Result is: %s' % (username, result['status']))

            if jsend.is_success(result):
                return jsonify(result), 201
            else:
                return jsonify(result), 404
        else:
            r = jsend.fail({'message': 'unauthorized'})
            return jsonify(r), 403
