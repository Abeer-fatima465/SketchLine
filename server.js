const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

// Generate a cryptographically secure secret
const generateSecret = () => crypto.randomBytes(32).toString('hex');

const app = express();
const port = 3000;

// Security middleware
app.use(helmet());
app.disable('x-powered-by');

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5 // limit each IP to 5 requests per windowMs
});

// Apply rate limiting to all routes
app.use(limiter);

// Session configuration
app.use(session({
  secret: generateSecret(),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    domain: process.env.DOMAIN || 'localhost'
  }
}));

// Middleware for parsing form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static files from the same directory as this script
app.use(express.static(__dirname));

// Custom 404 handler
app.use((req, res) => {
  res.status(404).send("Sorry can't find that!");
});

// Custom error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Route to serve the welcome page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Route to handle login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    // In production, this would connect to a database
    const user = await validateUser(username);
    
    if (!user || !(await comparePasswords(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    req.session.loggedIn = true;
    req.session.userId = user.id;
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Route to handle dashboard
app.get('/dashboard', (req, res) => {
  if (req.session.loggedIn) {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
  } else {
    res.redirect('/');
  }
});

// Route to handle logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.send('Error logging out');
    }
    res.redirect('/');
  });
});

// Route to handle sign-up
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  
  // Input validation
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // In production, this would connect to a database
    const hashedPassword = await hashPassword(password);
    // Here you would save the user to your database
    console.log('User created:', username, email);
    res.send('Sign-up successful! User created.');
  } catch (error) {
    console.error('Sign-up error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}/`);
});

// Helper functions for password management
async function hashPassword(password) {
  const salt = await crypto.randomBytes(16).toString('hex');
  const hash = crypto.createHmac('sha512', salt)
    .update(password)
    .digest('hex');
  return { salt, hash };
}

async function comparePasswords(password, hash) {
  const newHash = crypto.createHmac('sha512', hash.salt)
    .update(password)
    .digest('hex');
  return newHash === hash.hash;
}

async function validateUser(username) {
  // In production, this would query your database
  // For demonstration purposes, we'll use a mock user
  if (username === 'admin') {
    return { id: 1, password: await hashPassword('password') };
  }
  return null;
}