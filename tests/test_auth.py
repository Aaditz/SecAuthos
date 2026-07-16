def test_registration_login_and_protected_profile(client):
    data = {"name": "Ada Lovelace", "email": "ada@example.com", "password": "StrongPassword!123"}
    assert client.post("/api/v1/auth/register", json=data).status_code == 201
    login = client.post("/api/v1/auth/login", json={"email": data["email"], "password": data["password"]})
    assert login.status_code == 200
    token = login.get_json()["access_token"]
    assert client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
def test_weak_password_rejected(client):
    response = client.post("/api/v1/auth/register", json={"name":"Test User", "email":"test@example.com", "password":"weak"})
    assert response.status_code in (400, 422)
