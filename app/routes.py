import jsend

from app.api_models import *
from app import api, app, comodo, db, gssapi
from app.db_models import Certificate, Principles
from flask import g, jsonify, request
from flask_restplus import Resource
from app.cert import get_cn, get_sha256_hash

def user_authorized(username):
    if username in g.acl_list:
        app.logger.info('User: %s is authorized!' % username)
        return True
    else:
        app.logger.info('User: %s is denied!' % username)
        return False

    return None

@api.route('/comodo/v1.0/<int:certificate_id>')
@api.route('/comodo/v1.0/tls/<int:certificate_id>')
@api.doc(params={'certificate_id': 'The certificate ID'})
@api.response(404, 'Certificate not found')
class ComodoCertificate(Resource):
    @api.doc(body=certificate_model, )
    @api.response(200, 'Certificate', certificate_response_model)
    @gssapi.require_auth()
    def get(self, certificate_id, username=''):
        """Request the signed public key by Certificate ID"""
        if user_authorized(username):
            app.logger.info('User: %s is requesting a completed certificate, ID: %s' % (username, certificate_id))
            body = request.get_json()

            result = comodo.collect(cert_id=certificate_id, format_type=body['format_type'])

            app.logger.debug('User: %s request status: %s' % (username, result['status']))

            if result['status'] == 'success':
                # If the certificate is issued we insert it into the DB
                if result['data']['certificate_status'] == 'issued':
                    hash = get_sha256_hash(result['data']['certificate'])
                    cn = get_cn(result['data']['certificate'])
                    id = result['data']['certificate_id']
                    principle = Principles.query.filter_by(principle=username).first()
                    cert = Certificate(id=id, cert_sha256=hash, cert_fqdn=cn, principle=principle)
                    db.session.add(cert)
                    db.session.commit()

                return jsonify(result), 200
            else:
                return jsonify(result), 400
        else:
            r = jsend.fail({'message': 'unauthorized'})
            return jsonify(r), 403

    @api.response(200, 'Successful', revoke_response_model)
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

            if result['status'] == 'success':
                return jsonify(result), 200
            else:
                return jsonify(result), 400
        else:
            r = jsend.fail({'message': 'unauthorized'})
            return jsonify(r), 403


@api.route('/comodo/v1.0/tls')
class ComodoTLSRequestCertificate(Resource):
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

            app.logger.info('User: %s Result is: %s' % (username, result['status']))

            if result['status'] == 'success':
                return jsonify(result), 201
            else:
                return jsonify(result), 400
        else:
            r = jsend.fail({'message': 'unauthorized'})
            return jsonify(r), 403

    @api.response(200, 'Certificate information', certificate_info_response_model)
    @gssapi.require_auth()
    def get(self, username=''):
        """Retrieve information about the available certificates and server types"""

        if user_authorized(username):

            app.logger.debug('User: %s GET certificate information.' % username)

            formats = sorted(list(comodo.formats.keys()))
            format_type = sorted(comodo.format_type)

            result = comodo.get_cert_types()

            app.logger.debug('User: %s GET certificate information, result: %s.' % (username, result['status']))

            if result['status'] == 'success':
                r = jsend.success({'formats': formats, 'format_type': format_type,
                                   'cert_types': result['data']['types']})
                return jsonify(r), 200
            else:
                return jsonify(result), 400

        else:
            r = jsend.fail({'message': 'unauthorized'})
            return jsonify(r), 403


# @api.route('/comodo/v1.0/tls/hash/sha256/<string:hash')
# @api.doc(params={'hash': "The certificate's sha256 hash"})
# @api.response(404, 'Certificate not found')