from app import app, db
from app.cert import get_cn, get_sha256_hash
from app.db_models import Certificate, Principles


def add_certificate(id, sha256_hash, pem, principle):
    """
    This function adds a certificate entry to the DB associated with a principle. This function returns
    None on success or an exception will be raised on failure.

    :param int id: The certificate ID, this must be unique
    :param string sha256_hash: The SHA256 hash as a string
    :param string pem: The base 64 PEM formatted representation of the certificate
    :param string principle: The principle name, example 'FOO@EXAMPLE.COM'
    :return: None
    :rtype None:
    """

    # Get the CN of the certificate
    cn = get_cn(pem)

    p = Principles.query.filter_by(principle=principle).first()
    cert = Certificate(id=id, cert_sha256=sha256_hash, cert_fqdn=cn, principle=p)

    app.logger.debug('Adding cert: %s to DB with principle: %s' % (cert, principle))

    db.session.add(cert)
    db.session.commit()

    return None


def certificate_exists(principle, sha256_hash):
    """
    This function performs a DB query using the principle as the one and the certificates tied to that
    principle as the many. Meaning in short, it gives you all certificates issued to a given principle. A further
    query is then performed to find if a cert with the hash given already exists, if so the object is returned, if
    no certificate exists, None is returned.

    :param string principle: The principle name, example 'FOO@EXAMPLE.COM'
    :param string sha256_hash: The SHA256 hash as a string
    :return: Either the certificate object or None if it does not exist
    """
    app.logger.debug(principle)
    app.logger.debug(sha256_hash)
    app.logger.debug('Performing DB query for principle: %s with cert hash: %s' % (principle, sha256_hash))

    result = Principles.query.filter_by(principle=principle).first().certificates\
             .filter_by(cert_sha256=sha256_hash).first()

    app.logger.debug('Query result: %s' % result)

    return result
