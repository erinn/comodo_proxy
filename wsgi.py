from app import app, db
from app.db_models import Certificate, Principles

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'Certificate': Certificate, 'Principles': Principles}
