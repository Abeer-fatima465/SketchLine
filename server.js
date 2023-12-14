const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const app = express();
const port = 3000;

// Middleware for parsing form data
app.use(bodyParser.urlencoded({ extended: true }));

// Session middleware configuration
app.use(session({
    secret: 'your_secret_key', // Change this to a random secret string
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
}));

// Serve static files from the same directory as this script
app.use(express.static(__dirname));

// Route to serve the welcome page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'welcome.html'));
});

// Route to handle login
app.post('/login', (req, res) => {
    // For demonstration, username is 'admin' and password is 'password'
    // In a real app, you should validate against data in your database
    if (req.body.username === 'admin' && req.body.password === 'password') {
        req.session.loggedIn = true;
        res.send('Login successful!');
    } else {
        res.send('Invalid username or password');
    }
});

// Route to handle sign-up
app.post('/signup', (req, res) => {
    // Extracting user details from the request body
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
    console.log('User created:', username, email, password);

    // Sending a response back to the client
    res.send('Sign-up successful! User created.');

    // Here, you should add database handling code and proper password management
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
