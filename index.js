const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json()); 

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database');
});

const generateToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);
};

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  // Check if the user already exists
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (results.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password and save the user
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (email, password_hash) VALUES (?, ?)', 
      [email, hashedPassword], (err, result) => {
        if (err) throw err;
        res.status(201).json({ message: 'User created successfully' });
    });
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const user = results[0];

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate a JWT token
    const token = generateToken(user);
    db.query('INSERT INTO tokens (token, user_id) VALUES (?, ?)', [token, user.id], (err) => {
      if (err) throw err;
      res.json({ token });
    });
  });
});

app.post('/logout', (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(400).json({ message: 'No token provided' });

  // Verify the token to ensure it's valid
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }

    // Check if the token exists in the database
    db.query('SELECT * FROM tokens WHERE token = ? AND is_valid = TRUE', [token], (err, results) => {
      if (err) throw err;
      if (results.length === 0) {
        return res.status(404).json({ message: 'Token not found or already invalid' });
      }

      // Mark the token as invalid in the database
      db.query('UPDATE tokens SET is_valid = FALSE WHERE token = ?', [token], (err) => {
        if (err) throw err;
        res.json({ message: 'Logged out successfully' });
      });
    });
  });
});


const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required' });

  // Check if the token exists and is valid in the database
  db.query('SELECT * FROM tokens WHERE token = ? AND is_valid = TRUE', [token], (err, results) => {
    if (err) throw err;
    if (results.length === 0) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }

    // Verify the token using jwt
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ message: 'Invalid token' });
      req.user = user;
      next();
    });
  });
};


app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'Welcome to your profile', user: req.user });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
