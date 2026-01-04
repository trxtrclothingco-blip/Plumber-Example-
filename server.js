const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

// File to store users permanently
const USERS_FILE = path.join(__dirname, 'users.json');

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Helper: load users
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return {};
  const data = fs.readFileSync(USERS_FILE);
  return JSON.parse(data);
}

// Helper: save users
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ------------------ SIGNUP ------------------
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const users = loadUsers();
  if (users[email]) return res.status(400).json({ error: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  users[email] = { username, email, password: hashed };
  saveUsers(users);

  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username });
});

// ------------------ LOGIN ------------------
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'All fields are required' });

  const users = loadUsers();
  const user = users[email];
  if (!user) return res.status(400).json({ error: 'Invalid login' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Invalid login' });

  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username: user.username });
});

// ------------------ CHECK TOKEN ------------------
app.get('/check', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token provided' });

  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const users = loadUsers();
    const user = users[decoded.email];
    if (!user) return res.status(401).json({ error: 'Invalid token' });
    res.json({ ok: true, username: user.username });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// ------------------ START SERVER ------------------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
