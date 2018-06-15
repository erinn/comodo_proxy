from . import db

class Principles(db.Model):
    __tablename__ = 'kerberos_principles'

    id = db.Column(db.Integer, primary_key=True)
    principle = db.Column(db.String(64), unique=True)
    certificates = db.relationship('Certificate', backref='principle')

    def __repr__(self):
        return '<Principle {}>'.format(self.principle)

class Certificate(db.Model):
    __tablename__ = 'certificates'

    id = db.Column(db.Integer, primary_key= True)
    cert_fqdn = db.Column(db.Text(300))
    id_principles = db.Column(db.Integer, db.ForeignKey('principles.id'))

    def __repr__(self):
        return '<Certificate {}>'.format(self.certificate)