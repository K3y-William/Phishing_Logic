from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('config.py')

    from .routes import auth, scan, reports, settings
    app.register_blueprint(auth.bp)
    # app.register_blueprint(scan.bp)
    # app.register_blueprint(reports.bp)
    # app.register_blueprint(settings.bp)

    return app