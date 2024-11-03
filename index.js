// index.js
const express = require('express');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const axios = require('axios');

require('dotenv').config();  // Load environment variables
const db = require('./db');


const app = express();
const PORT = process.env.PORT || 5431; //on server 5431

// Security middleware
app.use(helmet());  // Adds security headers
app.use(cookieParser());
// CSRF protection middleware
// const csrfProtection = csrf({ cookie: true });
// app.use(csrfProtection);

// Enable CORS for requests from http://localhost:3000
app.use(cors({
  origin: ['https://farawebdata.ir', 'http://localhost:3000'], // Allow only this origin 
  methods: 'GET,POST', // Allow only GET and POST requests
  credentials: true // Allow cookies to be sent
}));

// Rate limiting middleware for DDoS
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/submit', limiter);

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Route to display the form (for CSRF token demonstration)
// app.get('/form', (req, res) => {
//   res.send(`<form action="/submit" method="POST">
//               <input type="hidden" name="_csrf" value="${req.csrfToken()}">
//               Name: <input type="text" name="name"><br>
//               Mobile: <input type="text" name="mobile"><br>
//               Message: <textarea name="message"></textarea><br>
//               <button type="submit">Submit</button>
//             </form>`);
// });

// Route to handle form submissions with validation and sanitization for XSS & SQL Injection protection
app.post(
  '/submit',
  [
    body('name').trim().isLength({ min: 1 }).withMessage('Name is required.').escape(),
    body('mobile').trim().isLength({ min: 11, max: 12 }).withMessage('Mobile number must be at least 10 digits.').escape(),
    body('message').trim().isLength({ min: 1 }).withMessage('Message is required.').escape(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, mobile, message } = req.body;

    const query = 'INSERT INTO submissions (name, mobile, message) VALUES (?, ?, ?)';
    db.query(query, [name, mobile, message], (err, results) => {
      if (err) {
        console.error('Error inserting data:', err);
        return res.status(500).send({ error: 'Database error' });
      }
      res.status(200).send({ message: 'Submission successful', submissionId: results.insertId });
    });
  }
);

// Route to fetch all submissions
app.get('/webapp/submissions', (req, res) => {
  const query = 'SELECT * FROM submissions';

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching submissions:', err);
      return res.status(500).send({ error: 'Database error' });
    }
    res.json(results);
  });
});




//contactUs

app.post(
  '/formus',
  [
    body('name').trim().isLength({ min: 1 }).withMessage('نام الزامی است').escape(),
    body('mobile').trim().isLength({ min: 11, max: 12 }).withMessage('موبایل باید 11 رقمی باشد').escape(),
    body('preferences').isArray().withMessage('Preferences must be an array'),
  body('preferences.*').isIn(['وبسایت', 'اپلیکیشن', 'داشبورد', 'سایر']).withMessage('Invalid preference option'),

  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, mobile, preferences } = req.body;
    const preferencesStr = preferences.join(',');

    const query = `INSERT INTO contactform (name, mobile, preferences) VALUES (?, ?, ?)`;
    db.query(query,  [name, mobile, preferencesStr], (err, results) => {
      if (err) {
        console.error('Error inserting data:', err);
        return res.status(500).send({ error: 'Database error' });
      }
      res.status(200).send({ message: 'درخواست شما ارسال شد. منتظر تماس ما باشید', submissionId: results.insertId });
    });
  }
);

// Route to fetch all contactforms
app.get('/webapp/contactforms', (req, res) => {
  const query = 'SELECT * FROM contactform';

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching submissions:', err);
      return res.status(500).send({ error: 'Database error' });
    }
    res.json(results);
  });
});



// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on :${PORT}`);
});
