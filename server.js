// server.js — Step 2: real accounts (register + login) using PostgreSQL
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Database connection ──
// DATABASE_URL must be set in Render's Environment settings
// (use the "Internal Database URL" from your Render Postgres instance)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── Middleware ──
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// ── Helper: require login ──
function requireLogin(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/');
}

// Protect rooms.html — must come BEFORE express.static so it isn't
// served directly to logged-out visitors
app.get('/rooms.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'rooms.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

// ── Routes ──

// Register a new account (uses the existing "users" table)
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2)',
      [username, hash]
    );
    res.json({ success: true, message: 'Account created! You can now log in.' });
  } catch (err) {
    if (err.code === '23505') { // unique_violation
      return res.status(409).json({ error: 'That username is already taken.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// Log in
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({ success: true, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// Log out
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Check current session
app.get('/me', (req, res) => {
  if (req.session.userId) {
    res.json({ loggedIn: true, username: req.session.username });
  } else {
    res.json({ loggedIn: false });
  }
});

// Protected dashboard — redirects to the Rooms page
app.get('/dashboard', requireLogin, (req, res) => {
  res.redirect('/rooms.html');
});

// Provide the logged-in username to the Rooms page
app.get('/api/whoami', (req, res) => {
  if (req.session.userId) {
    res.json({ loggedIn: true, username: req.session.username });
  } else {
    res.json({ loggedIn: false });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
