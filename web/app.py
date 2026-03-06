import os

from flask import Flask

try:
    from .routes import web_bp
except ImportError:
    from web.routes import web_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me-for-production")
    app.register_blueprint(web_bp)
    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("FLASK_PORT", "5000")), debug=True)
