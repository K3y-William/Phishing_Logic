from flask import Flask
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
<<<<<<< HEAD
    CORS(app, origins=["http://localhost:8081"], supports_credentials=True)
=======
    CORS(app)
>>>>>>> b6cd24ea57c259fe358da2cbb5f76de37ce8f67b
    app.secret_key = "secret_key"
    app.config.from_pyfile('config.py')

    from .routes import auth, scan, reports, settings
    app.register_blueprint(auth.bp)
    app.register_blueprint(scan.bp)
    # app.register_blueprint(reports.bp)
    # app.register_blueprint(settings.bp)

    return app