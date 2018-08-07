from app import api
from flask_restplus import fields

# The following models define the input and output, this mainly aids in documentation for
# OpenAPI/Swagger

# All responses should inherit the status_response_model, this is basically jsend format, see here:
# https://labs.omniti.com/labs/jsend
status_response_model = api.model('Status Response',
                                  {'status': fields.String(description='The Status Message', example='success')})


csr_model = api.model('CSR Model',
                      {'cert_type_name':
                       fields.String(required=True,
                                     description='The full cert type name', example='Comodo Unified Communications Certificate'),
                       'csr':
                       fields.String(required=True, description='The Certificate Signing Request',
                                     example='-----BEGIN CERTIFICATE REQUEST-----\n[CSR GOES HERE]\n'
                                             '-----END CERTIFICATE REQUEST-----'),
                       'server_type':
                       fields.String(required=True,
                                     description='The type of server for the TLS certificate',
                                     example='Apache/ModSSL'),
                       'subject_alt_names':
                       fields.String(required=True,
                                     description='Subject Alternative Names separated by a ",".',
                                     example='1.example.com,2.example.com'),
                       'term': fields.Integer(required=True,
                                              description='The term in days, for the certificate', min=365, max=730,
                                              example=730)
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
                                                            example='x509CO'),
                              }
                             )

certificate_info_data = api.model('Certificate Info Data Model',
                                  {'formats': fields.List(
                                               fields.String(description='Comodo supported certificate formats',
                                                             example='Apache/ModSSL')),
                                   'format_type': fields.List(
                                                   fields.String(description='Comodo supported format types',
                                                                 example='x509CO')),
                                   'cert_types': fields.List(
                                                   fields.String(
                                                       description='The certificate types supported for the user',
                                                       example='Comodo Unified Communications Certificate')),
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
