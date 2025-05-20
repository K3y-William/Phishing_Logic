from flask import Flask
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
<<<<<<< HEAD
    app.secret_key = 'your-very-secret-key'
=======
    CORS(app)
    app.secret_key = "secret_key"
>>>>>>> 6df77a2
    app.config.from_pyfile('config.py')

    from .routes import auth, scan, reports, settings
    app.register_blueprint(auth.bp)
    # app.register_blueprint(scan.bp)
    # app.register_blueprint(reports.bp)
    # app.register_blueprint(settings.bp)

    return app