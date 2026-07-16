# SecAuthos — Secure Authentication System

SecAuthos is a secure authentication project built with Flask. It demonstrates user registration, bcrypt password hashing, JWT authentication, protected routes, and session management in a clean browser interface and documented REST API.

This project was built as a portfolio-ready implementation of a **Secure Authentication System** using Python, Flask, JWT, bcrypt, and PostgreSQL.

## Features

- User registration with email and strong-password validation
- Secure password hashing using bcrypt (passwords are never stored in plaintext)
- JWT access tokens and refresh tokens
- Protected authenticated user profile endpoint
- Logout with JWT revocation
- Active session tracking and session listing
- Password-change endpoint with password-history protection
- PostgreSQL-ready SQLAlchemy models and Alembic migration support
- Interactive Swagger/OpenAPI API documentation
- Simple Bootstrap login, registration, and dashboard interface
- Docker and Docker Compose configuration
- pytest tests for registration, login, and protected endpoints

## Tech Stack

| Category | Technology |
| --- | --- |
| Language | Python 3.10+ |
| Backend | Flask, Flask Blueprints |
| Database | PostgreSQL, SQLAlchemy ORM |
| Authentication | Flask-JWT-Extended / PyJWT |
| Password Security | bcrypt |
| Validation | Marshmallow |
| API Documentation | Flask-Smorest / Swagger OpenAPI |
| Testing | pytest |
| Deployment | Docker, Docker Compose, Gunicorn |

## Project Structure

```text
SecAuthos/
├── app/
│   ├── auth/             # Registration, login, logout, token endpoints
│   ├── users/            # Profile and active-session endpoints
│   ├── models/           # SQLAlchemy database models
│   ├── schemas/          # Request validation schemas
│   ├── services/         # Password, JWT, session, audit helpers
│   ├── templates/        # Bootstrap browser interface
│   ├── config.py         # Environment-based configuration
│   └── extensions.py     # Flask extension setup
├── tests/                # pytest tests
├── migrations/           # Alembic migration files
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── wsgi.py
```

## Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/SecAuthos.git
cd SecAuthos
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Set unique, long values for `SECRET_KEY` and `JWT_SECRET_KEY`. Never commit your `.env` file.

### 5. Set up the database

For local development, the application creates its tables automatically when using the default SQLite database.

For PostgreSQL, set `DATABASE_URL` in `.env`, then create versioned migrations:

```bash
flask --app wsgi db init
flask --app wsgi db migrate -m "initial schema"
flask --app wsgi db upgrade
```

### 6. Run the application

```bash
flask --app wsgi run
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## How to Test the Application

1. Open the application in your browser.
2. Select the **Register** tab.
3. Enter a name, email, and a strong password such as `StrongPassword!123`.
4. Select the **Login** tab and sign in with the same credentials.
5. The dashboard displays your authenticated profile and lets you view active sessions.
6. Click **Logout** to revoke the current token and end the browser session.

Swagger API documentation is available at:

```text
http://127.0.0.1:5000/docs
```

## API Endpoints

All endpoints use the `/api/v1` prefix.

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/auth/register` | Register a new user |
| POST | `/auth/login` | Authenticate and receive JWT tokens |
| POST | `/auth/refresh` | Refresh/rotate authentication token |
| POST | `/auth/logout` | Revoke current access token |
| POST | `/auth/password/change` | Change the authenticated user password |
| GET | `/users/me` | Get authenticated user profile |
| PATCH | `/users/me` | Update authenticated user profile |
| GET | `/users/me/sessions` | List active sessions |
| DELETE | `/users/me/sessions/{id}` | End an active session |
| GET | `/health` | Application health check |

## Security Design

- **bcrypt hashing:** Passwords are salted and hashed with bcrypt before database storage.
- **Strong password policy:** Passwords must be at least 12 characters and include uppercase, lowercase, number, and special characters.
- **JWT authentication:** The API issues short-lived access tokens and refresh tokens.
- **Token revocation:** Logout blacklists the token identifier, preventing reuse.
- **Refresh rotation:** A refresh token is revoked when used and replaced with a new one.
- **Session tracking:** Each login creates a server-side session record that can be listed or terminated.
- **Input validation:** Marshmallow validates registration, login, password, and profile payloads.
- **SQL injection protection:** SQLAlchemy ORM parameterizes database queries.
- **Environment secrets:** Signing secrets and database URLs are loaded from environment variables.

## Run with Docker

```bash
cp .env.example .env
docker compose up --build
```

The application will be available at [http://localhost:8000](http://localhost:8000).

For PostgreSQL schema setup inside Docker:

```bash
docker compose exec api flask --app wsgi db init
docker compose exec api flask --app wsgi db migrate -m "initial schema"
docker compose exec api flask --app wsgi db upgrade
```

## Testing

Run the automated tests:

```bash
python -m pytest -q
```

The included tests cover successful registration, successful login, JWT-protected profile access, and weak-password rejection.

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Flask application secret |
| `JWT_SECRET_KEY` | JWT signing secret |
| `DATABASE_URL` | PostgreSQL connection URL |
| `PASSWORD_PEPPER` | Optional additional password secret |
| `ALLOWED_ORIGINS` | Allowed CORS origins |
| `TALISMAN_ENABLED` | Enables HTTPS/CSP security headers in deployed environments |

## Future Improvements

- Email verification and password reset emails
- Multi-factor authentication interface
- Role-based admin dashboard
- Redis-backed distributed session and rate-limit storage
- OAuth login providers

## License

For educational and portfolio use. Add an open-source license before public distribution.
