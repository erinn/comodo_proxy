from app import app, db
from app.cert import get_cn
from app.db_models import Certificate, Principles
from sqlalchemy.exc import IntegrityError

import jsend


def add_certificate(id, sha256_hash, pem, principle):
    """
    This function adds a certificate entry to the DB associated with a principle. This function returns
    None on success or a jsend formatted dictionary with the error on failure.

    :param int id: The certificate ID, this must be unique
    :param string sha256_hash: The SHA256 hash as a string
    :param string pem: The base 64 PEM formatted representation of the certificate
    :param string principle: The principle name, example 'FOO@EXAMPLE.COM'
    :return: Either None for no error, or a jsend formatted dictionary for an error.
    :rtype string:
    """

    # Get the CN of the certificate
    cn = get_cn(pem)

    p = Principles.query.filter_by(principle=principle).first()
    cert = Certificate(id=id, cert_sha256=sha256_hash, cert_fqdn=cn, principle=p)

    app.logger.debug('Attempting to add certificate: %s to DB with principle: %s' % (cert, principle))

    try:
        db.session.add(cert)
        db.session.commit()
    except IntegrityError:
        # TODO: Expand logger info.
        app.logger.info('A DB Key collision occurred.')
        return jsend.error('A DB key collision has occurred. If you are debugging the helper by hand, this is expected '
                           'and indicates everything is working. Otherwise, figure out what went wrong on the server.')
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

    result = Principles.query.filter_by(principle=principle).first().certificates \
        .filter_by(cert_sha256=sha256_hash).first()

    app.logger.debug('Query result: %s' % result)

    return result
