# Secure AI Chatbot

A production-ready, security-hardened AI chatbot built with Flask, SQLite, and Groq API.

## Features

- **User Authentication** — Secure registration/login with bcrypt password hashing
- **Session Management** — Server-side sessions with HttpOnly cookies
- **User Isolation** — Each user can only access their own chat history (RLS equivalent)
- **Rate Limiting** — 10 requests/minute per user on the chat endpoint
- **XSS Prevention** — Frontend uses `textContent` only, no raw `innerHTML`
- **SQL Injection Protection** — 100% parameterized queries
- **Environment Variables** — All secrets managed via `.env`

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask |
| Database | SQLite |
| AI Model | Groq (Llama 3.3 70B) |
| Auth | Werkzeug (bcrypt) |
| Rate Limiting | Flask-Limiter |

## Quick Start

```bash
# 1. Clone
git clone https://github.com/patrickdesmondU/secure-ai-chatbot.git
cd secure-ai-chatbot

# 2. Create virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your keys

# 5. Initialize database
python -c "from app import init_db; init_db()"

# 6. Run
python app.py
```

Open http://localhost:5000 in your browser.

## Environment Variables

Create a `.env` file:

```env
FLASK_SECRET_KEY=your-64-char-random-hex-string
GROQ_API_KEY=your-groq-api-key
FLASK_ENV=development
```

- **FLASK_SECRET_KEY**: Generate with `python -c "import secrets; print(secrets.token_hex(32))"`
- **GROQ_API_KEY**: Get free at [console.groq.com/keys](https://console.groq.com/keys)

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | No | Create account |
| POST | `/api/auth/login` | No | Log in |
| POST | `/api/auth/logout` | Yes | Log out |
| GET | `/api/auth/me` | Yes | Current user |
| POST | `/api/chat` | Yes | Send message to AI |
| GET | `/api/history` | Yes | Get chat history |
| DELETE | `/api/history` | Yes | Clear history |

## Security Checklist

- [x] Passwords hashed with bcrypt
- [x] Session cookies are HttpOnly and SameSite=Lax
- [x] All database queries are parameterized
- [x] Rate limiting on chat endpoint
- [x] XSS-safe DOM manipulation (`textContent` only)
- [x] No secrets committed to Git

## License

MIT
