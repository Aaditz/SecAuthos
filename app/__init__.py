from flask import Flask, render_template
from flask_cors import CORS
from flask_talisman import Talisman
from .config import config
from .extensions import db, migrate, jwt, limiter, api
from .auth.routes import blp as auth_blp
from .users.routes import blp as users_blp
from .admin.routes import blp as admin_blp
from .security.routes import blp as security_blp
from .security.jwt_callbacks import register_jwt_callbacks

def create_app(config_name=None):
    app = Flask(__name__)
    app.config.from_object(config[config_name or "default"])
    db.init_app(app); migrate.init_app(app, db); jwt.init_app(app); limiter.init_app(app)
    CORS(app, origins=app.config["ALLOWED_ORIGINS"].split(","), supports_credentials=False)
    if app.config["TALISMAN_ENABLED"]:
        Talisman(app, content_security_policy={"default-src": "'self'"}, force_https=not app.debug)
    api.init_app(app)
    for blueprint in (auth_blp, users_blp, admin_blp, security_blp): api.register_blueprint(blueprint)
    register_jwt_callbacks(jwt)
    # Local development convenience. Production deployments use Alembic migrations.
    if app.debug or app.testing:
        with app.app_context():
            db.create_all()
    @app.get("/")
    def index():
        return render_template("index.html")
    @app.get("/health")
    def health(): return {"status": "ok"}, 200
    return app
