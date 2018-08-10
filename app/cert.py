from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509


def get_sha256_hash(pem):
    '''
    This function takes a PEM encoded string and returns the SHA256 hash of the certificate as a hex encoded string.

    :param str pem: The PEM encoded certificate as a string
    :return: The SHA 256 hash as a hex string
    :rtype: str
    '''

    cert = x509.load_pem_x509_certificate(pem.encode('utf-8'), default_backend())
    h = cert.fingerprint(hashes.SHA256())

    return h.hex()


def get_cn(pem):
    '''
    This function takes a pem encoded string and returns the Common Name (CN) for the given certificate.

    :param str pem: The PEM encoded certificate as a string
    :return: The certificate common name
    :rtype: str
    '''

    cert = x509.load_pem_x509_certificate(pem.encode('utf-8'), default_backend())
    oid = x509.ObjectIdentifier('2.5.4.3')
    cn = cert.subject.get_attributes_for_oid(oid)[0].value

    return cn
