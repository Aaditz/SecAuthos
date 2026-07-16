import math, re
from flask_smorest import Blueprint
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import User
from app.services.security import security_score
blp = Blueprint("security", __name__, url_prefix="/api/v1/security", description="Security center and defensive tooling")
@blp.route("/center", methods=["GET"])
@jwt_required()
def center():
    u = User.query.get_or_404(get_jwt_identity()); score, tips = security_score(u); risk = "low" if score >= 70 else "medium" if score >= 40 else "high"
    return {"security_score": score, "risk_level": risk, "recommendations": tips, "mfa_enabled": u.mfa_enabled}
@blp.route("/password-entropy", methods=["POST"])
def entropy():
    from flask import request
    password = (request.get_json(silent=True) or {}).get("password", "")
    charset = (26 if re.search('[a-z]', password) else 0) + (26 if re.search('[A-Z]', password) else 0) + (10 if re.search(r'\d', password) else 0) + (33 if re.search(r'[^\w\s]', password) else 0)
    bits = round(len(password) * math.log2(max(charset, 1)), 1)
    return {"entropy_bits": bits, "rating": "strong" if bits >= 60 else "moderate" if bits >= 40 else "weak"}
@blp.route("/attack-simulator", methods=["POST"])
@jwt_required()
def simulator():
    from flask import request
    attack = (request.get_json(silent=True) or {}).get("attack", "")
    controls = {"brute_force":"Rate limits and account lockouts block repeated attempts.", "sql_injection":"SQLAlchemy parameterizes all ORM queries.", "xss":"Validation and CSP reduce XSS exposure.", "replay_attack":"JTI revocation and refresh rotation reject replayed tokens.", "expired_jwt":"JWT expiry validation rejects expired credentials."}
    return {"attack": attack, "blocked": attack in controls, "control": controls.get(attack, "Unknown simulation.")}
