from . import db


class Principles(db.Model):
    __tablename__ = 'principles'

    id = db.Column(db.Integer, primary_key=True)
    principle = db.Column(db.String(64), unique=True)
    active = db.Column(db.Boolean)
    certificates = db.relationship('Certificate', backref='principle', lazy='dynamic')

    def __repr__(self):
        return '<Principle:{}, Active:{}>'.format(self.principle, self.active)

class Certificate(db.Model):
    __tablename__ = 'certificates'

    id = db.Column(db.Integer, primary_key= True)
    cert_fqdn = db.Column(db.String(300))
    cert_sha256 = db.Column(db.String(64))
    principle_id = db.Column(db.Integer, db.ForeignKey('principles.id'))

    def __repr__(self):
        return '<Certificate:{}, SHA256:{}>'.format(self.cert_fqdn, self.cert_sha256)