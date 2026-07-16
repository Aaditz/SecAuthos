from app.models import BlocklistedToken, UserSession
from app.models.identity import now, utc
def register_jwt_callbacks(jwt):
    @jwt.token_in_blocklist_loader
    def blocked(_, payload):
        if BlocklistedToken.query.get(payload["jti"]): return True
        sid=payload.get("sid"); session=UserSession.query.get(sid) if sid else None
        return bool(session and (session.terminated_at or utc(session.expires_at) < now()))
    @jwt.revoked_token_loader
    def revoked(_, __): return {"error":"token_revoked","message":"Token is no longer valid."}, 401
    @jwt.invalid_token_loader
    def invalid(reason): return {"error":"invalid_token","message":reason}, 422
    @jwt.unauthorized_loader
    def missing(reason): return {"error":"authorization_required","message":reason}, 401
