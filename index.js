const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail')
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const HOST = process.env.APP_HOST;
const PORT = process.env.APP_PORT || 8080;

app.use(express.json());

const isDevelopment = process.env.ENVIRONMENT === 'development';
let db = null;
if (isDevelopment) {
  db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
  });
} else {
  db = mysql.createConnection({
    socketPath: process.env.INSTANCE_UNIX_SOCKET,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });
}

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
  

  // Build the confirmation URL
  const confirmationUrl = isDevelopment
    ? `${HOST}:${PORT}/confirm/${token}`
    : `${HOST}/confirm/${token}`;

  const msg = {
    to: email, // Change to your recipient
    from: process.env.SENDGRID_FROM_EMAIL, // Change to your verified sender
    subject: 'SobatKendara - Confirm your registration',
    text: `Click the link to confirm your registration: ${confirmationUrl}`,
    
  };
  //html: '<strong>and easy to do anywhere, even with Node.js</strong>',
  return sgMail.send(msg);
};

const generateToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET);
};

app.post('/signup', async (req, res) => {
  try {
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
          if (err) return next(err);
          // Send confirmation email
          try {
            await sendConfirmationEmail(email, confirmationToken);
            res.status(201).json({ message: 'Signup successful, please confirm your email' });
          } catch (error) {
            res.status(500).json({ message: 'Failed to send confirmation email' });
          }
      });
    });
  } catch (error) {
    next(error); // Handle unexpected errors
  }
});

app.get('/test', (req, res) => {
  const tk = "testaja"
  const confirmationUrl = `http://localhost:${PORT}/confirm/${tk}`;
  console.log(confirmationUrl);
  console.log(`Click the link to confirm your registration: ${confirmationUrl}`);
});

// Confirm registration route
app.get('/confirm/:token', (req, res) => {
  try {
    const { token } = req.params;

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return res.status(400).json({ message: 'Invalid or expired token' });

      // Activate the user
      db.query('UPDATE users SET is_active = 1, confirmation_token = NULL WHERE confirmation_token = ?', [token], (err, result) => {
        if (err) return next(err);
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: 'User not found or already activated' });
        }
        res.json({ message: 'Account successfully activated' });
      });
    });
  } catch (error) {
    next(error); // Handle unexpected errors
  }
});

// Generate a 6-digit OTP
const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// Send OTP via email
const sendOTPEmail = (email, otp) => {
  const msg = {
    to: email,
    from: process.env.SENDGRID_FROM_EMAIL,
    subject: 'SobatKendara - Your OTP for Password Reset',
    text: `Use this OTP to reset your password: ${otp}`,
  };
  return sgMail.send(msg);
};

// Request OTP endpoint
app.post('/request-otp', (req, res) => {
  try {
    const { email } = req.body;

    // Find user by email
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) return next(err);
      if (results.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      const otp = generateOTP();
      const expiration = new Date(Date.now() + 10 * 60000); // OTP valid for 10 minutes

      // Store OTP and expiration in the database
      db.query(
        'UPDATE users SET otp = ?, otp_expiration = ? WHERE email = ?',
        [otp, expiration, email],
        async (err) => {
          if (err) return next(err);

          // Send OTP via email
          try {
            await sendOTPEmail(email, otp);
            res.json({ message: 'OTP sent to your email' });
          } catch (error) {
            console.error('Error sending OTP:', error);
            res.status(500).json({ message: 'Failed to send OTP' });
          }
        }
      );
    });
  } catch (error) {
    next(error); // Handle unexpected errors
  }
});

app.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, new_password } = req.body;

    // Find user by email and verify OTP
    db.query('SELECT * FROM users WHERE email = ? AND otp = ?', [email, otp], async (err, results) => {
      if (err) return next(err);
      if (results.length === 0) {
        return res.status(400).json({ message: 'Invalid OTP or email' });
      }

      const user = results[0];

      // Check if OTP has expired
      if (new Date() > new Date(user.otp_expiration)) {
        return res.status(400).json({ message: 'OTP has expired' });
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(new_password, 10);

      // Update the user's password and clear the OTP
      db.query(
        'UPDATE users SET password_hash = ?, otp = NULL, otp_expiration = NULL WHERE email = ?',
        [hashedPassword, email],
        (err) => {
          if (err) return next(err);
          res.json({ message: 'Password reset successfully' });
        }
      );
    });
  } catch (error) {
    next(error); // Handle unexpected errors
  }
});

app.post('/login', (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) return next(err);
      if (results.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      const user = results[0];

      // Check if the user is active
      if (!user.is_active) {
        return res.status(403).json({ message: 'Please confirm your email to activate your account' });
      }

      // Compare passwords
      const isPasswordValid = await bcrypt.compare(password, user.password_hash);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      // Generate a JWT token
      const token = generateToken(user);
      db.query('INSERT INTO tokens (token, user_id) VALUES (?, ?)', [token, user.id], (err) => {
        if (err) return next(err);
        res.json({ token });
      });
    });
  } catch (error) {
    next(error); // Handle unexpected errors
  }
});

app.post('/logout', (req, res) => {
  try {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(400).json({ message: 'No token provided' });

    // Verify the token to ensure it's valid
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid token' });
      }

      // Check if the token exists in the database
      db.query('SELECT * FROM tokens WHERE token = ? AND is_valid = TRUE', [token], (err, results) => {
        if (err) return next(err);
        if (results.length === 0) {
          return res.status(404).json({ message: 'Token not found or already invalid' });
        }

        // Mark the token as invalid in the database
        db.query('UPDATE tokens SET is_valid = FALSE WHERE token = ?', [token], (err) => {
          if (err) return next(err);
          res.json({ message: 'Logged out successfully' });
        });
      });
    });
  } catch (error) {
    next(error); // Handle unexpected errors
  }
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


// Profile endpoint to fetch user details
app.get('/profile', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id; // Extract user ID from JWT token

    // Query to fetch user details
    db.query(
      'SELECT id, email, additional_email, created_at FROM users WHERE id = ?',
      [userId],
      (err, results) => {
        if (err) return next(err);

        if (results.length === 0) {
          return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0]; // Get the user details

        // Send the user properties as response
        res.json({
          id: user.id,
          email: user.email,
          additional_email: user.additional_email,
          created_at: user.created_at,
        });
      }
    );
  } catch (error) {
    next(error); // Handle unexpected errors
  }
});

// Edit profile endpoint to update additional email
app.put('/edit-profile', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id; // Extract user ID from JWT token
    let { additional_email } = req.body; // Get additional email from request body

    // Handle empty string case by setting it to null
    if (additional_email !== undefined && additional_email.trim() === '') {
      additional_email = null;
    }

    // Construct the SQL query based on the presence of additional_email
    const sql = additional_email !== undefined
      ? 'UPDATE users SET additional_email = ? WHERE id = ?'
      : 'SELECT id FROM users WHERE id = ?'; // Dummy select if nothing to update

    const params = additional_email !== undefined
      ? [additional_email, userId]
      : [userId];


    // Update the additional_email field (can be null)
    db.query(sql, params, (err, result) => {
      if (err) return next(err);

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      // Fetch the updated user details
      db.query(
        'SELECT id, email, additional_email, created_at FROM users WHERE id = ?',
        [userId],
        (err, results) => {
          if (err) return next(err);

          const user = results[0];
          res.json({
            message: 'Profile updated successfully',
            user: {
              id: user.id,
              email: user.email,
              additional_email: user.additional_email,
              created_at: user.created_at,
            },
          });
        }
      );
    });
  } catch (error) {
    next(error); // Handle unexpected errors
  }
});



app.post('/change-password', authenticateToken, async (req, res) => {
  try {
    const { old_password, new_password } = req.body;
    const userId = req.user.id; // Extracted from the JWT token

    // Fetch the user's current password hash from the database
    db.query('SELECT password_hash FROM users WHERE id = ?', [userId], async (err, results) => {
      if (err) return next(err);

      if (results.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      const user = results[0];

      // Compare the current password with the stored hash
      const isPasswordValid = await bcrypt.compare(old_password, user.password_hash);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Current password is incorrect' });
      }

      // Hash the new password
      const hashedNewPassword = await bcrypt.hash(new_password, 10);

      // Update the user's password in the database
      db.query('UPDATE users SET password_hash = ? WHERE id = ?', [hashedNewPassword, userId], (err) => {
        if (err) return next(err);
        res.json({ message: 'Password changed successfully' });
      });
    });
  } catch (error) {
    next(error);
  }
});

// Send Alert endpoint
app.post('/send-alert', authenticateToken, (req, res) => {
  try {
    const userId = req.user.id; // Extract user ID from JWT token
    const { 
      event_timestamp, 
      sound_decibel_value, 
      sound_decibel_threshold, 
      shake_value, 
      shake_threshold, 
      gps_location 
    } = req.body;

    // Validate required parameters
    if (!event_timestamp || !gps_location) {
      return res.status(400).json({ message: 'Event timestamp and GPS location are required' });
    }

    // Ensure event_timestamp matches MySQL's expected format
    const timestampRegex = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
    if (!timestampRegex.test(event_timestamp)) {
      return res.status(400).json({
        message: 'Invalid timestamp format. Use YYYY-MM-DD HH:MM:SS',
      });
    }

    // Insert the alert data into the database
    db.query(
      `INSERT INTO alerts (user_id, event_timestamp, sound_decibel_value, sound_decibel_threshold, 
        shake_value, shake_threshold, gps_location) 
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [userId, event_timestamp, sound_decibel_value, sound_decibel_threshold, shake_value, shake_threshold, gps_location],
      async (err, result) => {
        if (err) return next(err); // Pass DB error to the error handler

        // Fetch the user’s email and additional email from the users table
        db.query('SELECT email, additional_email FROM users WHERE id = ?', [userId], async (err, results) => {
          if (err) return next(err); // Handle query errors

          const user = results[0];
          const { email, additional_email } = user;

          // Prepare the email content
          const emailContent = {
            to: [email, additional_email].filter(Boolean), // Filter out null emails
            from: process.env.SENDGRID_FROM_EMAIL,
            subject: 'SobatKendara - Alert Notification',
            text: `Alert triggered by ${email}\n
                  Event Timestamp: ${event_timestamp}\n
                  GPS Location: ${gps_location}`,
          };

          try {
            // Send the email
            await sgMail.send(emailContent);
            res.status(201).json({ message: 'Alert recorded and email sent successfully' });
          } catch (error) {
            console.error('Error sending email:', error);
            res.status(500).json({ message: 'Failed to send alert email' });
          }
        });
      }
    );
  } catch (error) {
    next(error); // Handle unexpected errors
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err); // Log the error for debugging
  res.status(500).json({
    message: 'An unexpected error occurred. Please try again later.',
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
