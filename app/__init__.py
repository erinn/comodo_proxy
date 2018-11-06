import comodo_rest_api
import logging

from config import Config
from flask import Flask, g
from flask_gssapi import GSSAPI
from flask_migrate import Migrate
from flask_restplus import Api
from flask_sqlalchemy import SQLAlchemy
from raven.contrib.flask import Sentry

__version__ = '0.5.4'

app = Flask(__name__)

# SENTRY_DSN must be defined as an environment variable, if not, sentry will simply not function (which is fine),
# see here: https://docs.sentry.io/clients/python/integrations/flask/
sentry = Sentry(app)

# Import the configuration settings
app.config.from_object(Config)
api = Api(app)
gssapi = GSSAPI(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
comodo = comodo_rest_api.ComodoTLSService(api_url=app.config['COMODO_API_URL'],
                                          customer_login_uri=app.config['COMODO_CUSTOMER_LOGIN_URI'],
                                          login=app.config['COMODO_LOGIN'],
                                          org_id=app.config['COMODO_ORG_ID'],
                                          password=app.config['COMODO_PASSWORD'],
                                          client_cert_auth=app.config['COMODO_CLIENT_CERT_AUTH'],
                                          client_public_certificate=app.config['COMODO_CLIENT_PUBLIC_CERT'],
                                          client_private_key=app.config['COMODO_CLIENT_PRIVATE_KEY']
                                          )

from app import db_models, routes
from app.db_models import Principles, Certificate


@app.before_request
def populate_acl():
    """
    This function populates the ACL list from the DB before each request (as the DB may change without
    the apps knowledge).

    This function takes no arguments and returns nothing

    :return: None
    """
    result = []

    for i in Principles.query.filter(Principles.active == True):
        result.append(i.principle)

    app.logger.debug('All active principles: %s' % result)

    # Probably a security bug in here on the part of the requests-gssapi module, it fails open with an empty list
    # not closed.
    if len(result) == 0:
        result = ['']

    g.acl_list = result

    return None


# Establish logging when running under gunicorn. If running standalone will function as a normal
# flask server.
if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

app.logger.info('comodo_proxy %s starting.' % __version__)
app.logger.debug('comodo_proxy config: %s' % app.config)
