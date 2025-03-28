require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const helmet = require('helmet');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const hsts = require('hsts');
const fs = require('fs');
const https = require('https');

const app = express();
const PORT_HTTP = process.env.PORT || 3000;
const PORT_HTTPS = 3443;

// Helmet for securing HTTP headers
app.use(helmet({
    xFrameOptions: { action: "deny" },
    strictTransportSecurity: {
        maxAge: 31556952, // 1 year
        preload: true
    }
}));

// Middleware for parsing request bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'default-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true in production
}));

// Initialize Passport and session
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/userAuth', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB connected!"))
.catch(err => console.log(err));

// User database (in-memory for this example)
const users = {};

// Passport configuration for Google OAuth
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
    const user = {
        id: profile.id,
        username: profile.displayName,
        role: 'user' // Default role
    };
    users[profile.id] = user; // Store user in memory
    return done(null, user);
}));

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, users[id]));

// Static file serving
app.use('/static', express.static('public', {
    setHeaders: (res, path) => {
        if (path.endsWith('.css')) {
            res.set('Cache-Control', 'max-age=86400');
        }
        if (path.endsWith('.jpg') || path.endsWith('.png')) {
            res.set('Cache-Control', 'max-age=2592000');
        }
    }
}));

// routes for google oauth
app.get('/', (req, res) => {
    res.send('<h1>Welcome to the Secure App!</h1><a href="/auth/google">Login with Google</a>');
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/dashboard');
    });

app.get('/dashboard', (req, res) => {
    if (req.isAuthenticated()) {
        res.send(`Welcome ${req.user.username}! <a href="/logout">Logout</a>`);
    } else {
        res.redirect('/');
    }
});

app.get('/logout', (req, res, next) => {
    req.logout(err => {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

// routes from phase one
app.get('/goals', (req, res) => {
    res.set('Cache-Control', 'max-age=900, public'); // cache for 15 minutes
    res.sendFile(path.join(__dirname, 'public/goals.html'));
});

app.get('/profile', (req, res) => {
    res.set('Cache-Control', 'max-age=3600, private'); // cache for 1 hour
    res.sendFile(path.join(__dirname, 'public/profile.html'));
});

// HTTPS configuration
const hstsOptions = {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
};

const options = {
    key: fs.readFileSync('hidden/private-key.pem'),
    cert: fs.readFileSync('hidden/certificate.pem'),
};

const httpsServer = https.createServer(options, (req, res) => {
    hsts(hstsOptions)(req, res, () => {
        app(req, res);
    });
});

// Start both HTTP and HTTPS servers
app.listen(PORT_HTTP, () => {
    console.log(`HTTP Server running at http://localhost:${PORT_HTTP}`);
});

httpsServer.listen(PORT_HTTPS, () => {
    console.log(`HTTPS Server running at https://localhost:${PORT_HTTPS}`);
});