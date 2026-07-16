from flask_smorest import Blueprint, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models import User, UserSession, AuditLog
from app.models.identity import now
from app.schemas.auth import ProfileSchema
from app.services.security import audit, security_score
blp=Blueprint("users",__name__,url_prefix="/api/v1/users",description="User account and session management")
@blp.route("/me",methods=["GET"])
@jwt_required()
def me():
 u=User.query.get_or_404(get_jwt_identity()); score,tips=security_score(u); return {"id":u.id,"email":u.email,"name":u.name,"roles":[r.name for r in u.roles],"mfa_enabled":u.mfa_enabled,"security_score":score,"recommendations":tips}
@blp.route("/me",methods=["PATCH"])
@jwt_required()
@blp.arguments(ProfileSchema)
def profile(data):
 u=User.query.get_or_404(get_jwt_identity()); u.name=data.get("name",u.name); audit("profile_updated",u.id); db.session.commit(); return {"message":"Profile updated."}
@blp.route("/me/sessions",methods=["GET"])
@jwt_required()
def sessions():
 rows=UserSession.query.filter_by(user_id=get_jwt_identity(),terminated_at=None).all(); return {"items":[{"id":x.id,"ip":x.ip_address,"user_agent":x.user_agent,"created_at":x.created_at.isoformat(),"last_seen_at":x.last_seen_at.isoformat()} for x in rows]}
@blp.route("/me/sessions/<session_id>",methods=["DELETE"])
@jwt_required()
def terminate(session_id):
 s=UserSession.query.filter_by(id=session_id,user_id=get_jwt_identity()).first_or_404(); s.terminated_at=now(); audit("session_terminated",s.user_id,session_id=session_id); db.session.commit(); return {"message":"Session terminated."}
@blp.route("/me/audit-logs",methods=["GET"])
@jwt_required()
def logs():
 rows=AuditLog.query.filter_by(user_id=get_jwt_identity()).order_by(AuditLog.created_at.desc()).limit(100).all(); return {"items":[{"event":x.event,"at":x.created_at.isoformat(),"ip":x.ip_address} for x in rows]}
