const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const hbs = require('hbs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'your_secret_key', resave: false, saveUninitialized: true ,cookie: { secure: false }}));
app.use(passport.initialize());
app.use(passport.session());
const users = [];
// Set up Handlebars as the view engine
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'views')));

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/dakshPortfolio', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const mongoUrl = 'mongodb://localhost:27017/dakshPortfolio';
const dbName = 'oauth';

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// Define the schema and model for experiences
const experienceSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
});

const Experience = mongoose.model('Experience', experienceSchema);

// Define the schema and model for users
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

//const User = require('./views/google');
const User = mongoose.model('User', userSchema);

// Endpoint to handle storing user details
app.post('/store-user', async (req, res) => {
  const user = req.body;

  if (!user || !user.id || !user.email || !user.name) {
    return res.status(400).send('Invalid user data');
  }

  try {
    // Check if user already exists
    let existingUser = await User.findOne({ id: user.id });

    if (existingUser) {
      // Update existing user
      existingUser.email = user.email;
      existingUser.name = user.name;
      existingUser.picture = user.picture;
      await existingUser.save();
    } else {
      // Create new user
      const newUser = new User({
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
      });

      await newUser.save();
    }

    res.send('User data stored successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error storing user data');
  }
});


// User Registration Route
app.post('/api/signup', async (req, res) => {
  const { fullName, username, email, password } = req.body;
  console.log("Received signup request:", req.body);

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log("User already exists with email:", email);
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = new User({
      fullName,
      username,
      email,
      password: hashedPassword,
    });

    // Save user to database
    await newUser.save();
    console.log("User created successfully");
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.error("Error during signup process:", err.message);
    res.status(500).send('Server error');
  }
});



// User Login Route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({email});
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, 'your_jwt_secret', { expiresIn: '1h' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        photo: user.photo  // Include the photo URL here
      }
    });

  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Logout error');
    }
    res.redirect('/login');
  });
});



app.get('/profile', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  try {
    const user = req.user;
    const experiences = await Experience.find({ userId: user._id });
    res.render('profile', { user, experiences });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});


app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

passport.use(new GoogleStrategy({
  clientID: '491404078269-lh2s6ohr9gpq5g5llm6tm3m0aknrb3df.apps.googleusercontent.com',
  clientSecret: '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',
  callbackURL: '/auth/google/callback'
},
(accessToken, refreshToken, profile, done) => {
  let user = users.find(user => user.id === profile.id);
  if (!user) {
    user = { id: profile.id, displayName: profile.displayName, email: profile.emails[0].value };
    users.push(user);
  }
  return done(null, user);
}
));

// Serialize user into session
passport.serializeUser((user, done) => {
done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser((id, done) => {
const user = users.find(user => user.id === id);
done(null, user);
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/index');  // Redirect to home page after successful login
  }
);

app.get('/index', (req, res) => {
  res.render('index.hbs', { user: req.user });
});

app.get('/login', (req, res) => {
  res.render('login.hbs');
});

// API Routes
app.get('/api/experience', async (req, res) => {
  try {
    const experiences = await Experience.find();
    res.json(experiences);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/experience', async (req, res) => {
  const experience = new Experience({
    title: req.body.title,
    description: req.body.description,
    startDate: req.body.startDate,
    endDate: req.body.endDate,
  });

  try {
    const newExperience = await experience.save();
    res.status(201).json(newExperience);
  } catch (err) {
    console.error(err);
    res.status(400).json({ message: err.message });
  }
});

// Routes to render Handlebars templates
app.get('/', (req, res) => {
  res.render('index'); 
});

app.get('/index', (req, res) => {
  res.render('index');
});


app.get('/about', (req, res) => {
  res.render('about'); 
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/sign-up', (req, res) => {
  res.render('sign-up');
});
app.get('/profile',(req,res)=>{
  res.render('profile');
});
app.get('/project',(req,res)=>{
  res.render('project');
});


const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is in use, trying another port...`);
    app.listen(0, () => {
      console.log(`Server is running on port ${server.address().port}`);
    });
  } else {
    throw err;
  }
});
