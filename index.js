const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail')
require('dotenv').config();

const app = express();
const HOST = process.env.APP_HOST;
const PORT = process.env.APP_PORT || 8080;

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

sgMail.setApiKey(process.env.SENDGRID_API_KEY)

// Generate a confirmation token
const generateConfirmationToken = () => {
  return jwt.sign({}, process.env.JWT_SECRET, { expiresIn: '1d' }); // Token valid for 1 day
};

// Send confirmation email
const sendConfirmationEmail = (email, token) => {
  const confirmationUrl = `http://${HOST}:${PORT}/confirm/${token}`;

  const msg = {
    to: email, // Change to your recipient
    from: 'fahrismumtazaahsan@mail.ugm.ac.id', // Change to your verified sender
    subject: 'SobatKendara - Confirm your registration',
    text: `Click the link to confirm your registration: ${confirmationUrl}`,
    
  }
  //html: '<strong>and easy to do anywhere, even with Node.js</strong>',
  return sgMail.send(msg)
};

const generateToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);
};

app.post('/signup', async (req, res) => {
  const { email, password, notif_email } = req.body;

  // Check if the user already exists
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (results.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password and save the user
    const hashedPassword = await bcrypt.hash(password, 10);
    const confirmationToken = generateConfirmationToken();

    db.query('INSERT INTO users (email, password_hash, additional_email, is_active, confirmation_token) VALUES (?, ?, ?, ?, ?)', 
      [email, hashedPassword, notif_email, 0, confirmationToken], async (err, result) => {
        if (err) throw err;
        // Send confirmation email
        try {
          await sendConfirmationEmail(email, confirmationToken);
          res.status(201).json({ message: 'Signup successful, please confirm your email' });
        } catch (error) {
          res.status(500).json({ message: 'Failed to send confirmation email' });
        }
    });
  });
});

app.get('/test', (req, res) => {
  const tk = "testaja"
  const confirmationUrl = `http://localhost:${PORT}/confirm/${tk}`;
  console.log(confirmationUrl);
  console.log(`Click the link to confirm your registration: ${confirmationUrl}`);
});

// Confirm registration route
app.get('/confirm/:token', (req, res) => {
  const { token } = req.params;

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(400).json({ message: 'Invalid or expired token' });

    // Activate the user
    db.query('UPDATE users SET is_active = 1, confirmation_token = NULL WHERE confirmation_token = ?', [token], (err, result) => {
      if (err) throw err;
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'User not found or already activated' });
      }
      res.json({ message: 'Account successfully activated' });
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
