const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
require('dotenv').config(); // Load environment variables

const app = express();

// Body-parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));

// Connect to MongoDB Atlas
const mongoURI = process.env.MONGODB_URI;

mongoose.connect(mongoURI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.log("Error: " + err));

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: mongoURI }),
  cookie: { secure: false, maxAge: 1000 * 60 * 30 } // Session expires after 30 minutes
}));

// Define schema and model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String },
  password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Serve registration form
app.get('/sign', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'sign.html'));
});

// Serve login form
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Handle registration
app.post('/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send('Error: Email already registered.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      email,
      phone,
      password: hashedPassword
    });

    await newUser.save();
    res.send('Registration successful! <a href="/login">Login here</a>');
  } catch (err) {
    res.status(400).send('Error: ' + err.message);
  }
});

// Handle login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send('Error: User not found.');
    }

    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.userId = user._id; // Store user ID in session
      console.log('User logged in. Session ID:', req.sessionID, 'User ID:', req.session.userId);
      res.redirect('/'); // Redirect to home page
    } else {
      res.status(400).send('Error: Incorrect password.');
    }
  } catch (err) {
    res.status(400).send('Error: ' + err.message);
  }
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    console.log('Authenticated. Session ID:', req.sessionID, 'User ID:', req.session.userId);
    return next();
  }
  console.log('Not authenticated. Redirecting to login.');
  res.redirect('/login'); // Redirect to login page if not authenticated
}

// Serve home page (or profile page)
app.get('/', isAuthenticated, (req, res) => {
  console.log('Serving home page. Session ID:', req.sessionID, 'User ID:', req.session.userId);
  res.sendFile(path.join(__dirname, 'public', 'index.html')); // Serve the home page
});

// Handle logout
app.get('/logout', isAuthenticated, (req, res) => {
  console.log('Logout route reached. Session ID:', req.sessionID);
  req.session.destroy((err) => {
    if (err) {
      console.log('Logout error:', err.message);
      return res.status(500).send('Error: ' + err.message);
    }
    console.log('User logged out. Session destroyed.');
    res.redirect('/logout-success'); // Redirect to logout success page
  });
});

// Serve logout success page
app.get('/logout-success', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'logout.html')); // Serve the logout success page
});

// 404 error handling
app.use((req, res, next) => {
  res.status(404).send('<h1>404 PAGE NOT FOUND</h1>');
});

// Start the server
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
