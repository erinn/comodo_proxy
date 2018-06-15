import comodo_api
import configparser
import logging
import pathlib

from config import Config
from flask import Flask, jsonify, request
from flask_gssapi import GSSAPI
from flask_migrate import Migrate
from flask_restplus import Resource, Api, fields
from flask_sqlalchemy import SQLAlchemy
from raven.contrib.flask import Sentry

app = Flask(__name__)
app.config.from_object(Config)
api = Api(app)
gssapi = GSSAPI(app)

db = SQLAlchemy()
migrate = Migrate()
comodo = comodo_api.ComodoTLSService(**kwargs)

from app import models, routes
