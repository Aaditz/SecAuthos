from flask_smorest import Blueprint
from app.extensions import db
from app.models import User, AuditLog, LoginAttempt
from app.security.decorators import permission_required
blp = Blueprint("admin", __name__, url_prefix="/api/v1/admin", description="Administrative security operations")
@blp.route("/dashboard", methods=["GET"])
@permission_required("view_dashboard")
def dashboard():
    return {"registered_users": User.query.count(), "locked_accounts": User.query.filter(User.locked_until.isnot(None)).count(), "failed_logins": LoginAttempt.query.filter_by(successful=False).count(), "audit_events": AuditLog.query.count()}
@blp.route("/users/<user_id>/lock", methods=["POST"])
@permission_required("manage_users")
def lock_user(user_id):
    u = User.query.get_or_404(user_id); u.is_admin_locked = True; db.session.commit(); return {"message": "Account permanently locked."}
