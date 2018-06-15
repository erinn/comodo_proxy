import jsend

from app import api, app, comodo, gssapi
from flask import Flask, jsonify, request


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

        app.logger.debug('User: %s CSR: %s, Server Type: %s, Subject Alt Names: %s, Term: %s,' %
                         (username, body['csr'], body['server_type'], body['subject_alt_names'], body['term']))

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

        app.logger.debug('GET ACL list: %s' % acl_list)

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

