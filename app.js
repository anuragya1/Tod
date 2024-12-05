
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const hbs = require('hbs');
const path = require('path');
const passport = require('passport');
const GitHubStrategy = require('passport-github').Strategy;
const session = require('express-session');
const dotenv = require('dotenv');
const TodoTask = require('./models/db');
const User = require('./models/User');
dotenv.config()

const app = express();
hbs.registerHelper('eq', (a, b) => String(a) === String(b));


app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));
hbs.registerPartials(path.join(__dirname, 'views/partials')); 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
const isAuthenticated = (req, res, next) => {
  if (req.session.user) return next();
  res.redirect('/login');
};

const mongoURI =process.env.DB_CONNECT;

const connectionParams = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
};

mongoose
  .connect(mongoURI, connectionParams)
  .then(() => app.listen(3000, () => console.log('Server is running on 3000')))
  .catch((error) => console.log(error));

app.use(
  session({
    secret: 'secretKey', 
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, 
  })
);
 
app.use(passport.initialize());
app.use(passport.session());


passport.use(new GitHubStrategy(
  {
    clientID: process.env.GITHUB_CLIENT_ID ,
    clientSecret: process.env.GITHUB_CLIENT_SECRET, 
     callbackURL:"https://tod-tv9i.onrender.com/auth/github/callback",
     scope: ["user:email"]
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const existingUser = await User.findOne({ githubId: profile.id });
      if (existingUser) {
        return done(null, existingUser);
      } 
            console.log("profile details = "+profile.email)
 const email = profile.emails?.[0]?.value;

      
      const newUser = new User({
        githubId: profile.id,
        username: profile.username,
        email: email,
      });

      await newUser.save();
      return done(null, newUser);
    } catch (err) {
      console.log(err);
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});


passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});


app.get('/', async (req, res) => {
  try {
    const tasks = await TodoTask.find({});
    res.render('landing', { todos: tasks, user: req.session.user }); 
  } catch (err) {
    console.log(err);
  }
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {

    const hashedPassword = await bcrypt.hash(password, 10);

 
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();
    res.redirect('/login'); 
  } catch (err) {
    console.log(err);
    res.render('signup', { error: 'User already exists or invalid input!' });
  }
});

app.get('/login', (req, res) => {
  res.render('login'); 
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {

    const user = await User.findOne({ username });
    if (!user) {
      return res.render('login', { error: 'Invalid username or password!' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render('login', { error: 'Invalid username or password!' });
    }
    req.session.user = user;
    res.redirect('/dashboard'); 
  } catch (err) {
    console.log(err);
    res.render('login', { error: 'An error occurred. Please try again!' });
  }
});


app.get('/auth/github', passport.authenticate('github'));

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  (req, res) => {

    req.session.user = req.user;
    res.redirect('/dashboard'); 
  }
);

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const tasks = await TodoTask.find({ userId: req.session.user._id }); 
    res.render('index', { todoTasks: tasks, user: req.session.user });
  } catch (err) {
    console.log(err);
  }
});


app.post('/add', isAuthenticated, async (req, res) => {
  const { content, priority } = req.body; 
  const todoTask = new TodoTask({
    content,
    userId: req.session.user._id,
    priority: priority || 'Medium', 
  });

  try {
    await todoTask.save();
    res.redirect('/dashboard');
  } catch (err) {
    console.log(err);
    res.redirect('/dashboard');
  }
});
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const { priority } = req.query; 
    
    let filter = { userId: req.session.user._id }; 
    if (priority && priority !== 'All') {
      filter.priority = priority; 
    }


    const tasks = await TodoTask.find(filter);
    res.render('index', { todoTasks: tasks, user: req.session.user, priority }); 
  } catch (err) {
    console.log(err);
  }
});


app
  .route('/edit/:id')
  .get(isAuthenticated, async (req, res) => {
    const id = req.params.id;
    try {
      const task = await TodoTask.findOne({ _id: id, userId: req.session.user._id }); 
      if (!task) {
        return res.status(403).send('Unauthorized access!');
      }
      const tasks = await TodoTask.find({ userId: req.session.user._id });
      res.render('todoEdit', { todoTasks: tasks, idTask: id, user: req.session.user });
    } catch (err) {
      console.log(err);
    }
  })
  .post(isAuthenticated, async (req, res) => {
    const id = req.params.id;
    try {
      const task = await TodoTask.findOneAndUpdate(
        { _id: id, userId: req.session.user._id }, 
        { content: req.body.content }
      );
      if (!task) {
        return res.status(403).send('Unauthorized access!');
      }
      res.redirect('/dashboard');
    } catch (err) {
      console.log(err);
    }
  });


app.get('/remove/:id', isAuthenticated, async (req, res) => {
  const id = req.params.id;
  try {
    const task = await TodoTask.findOneAndDelete({ _id: id, userId: req.session.user._id }); 
    if (!task) {
      return res.status(403).send('Unauthorized access!');
    }
    res.redirect('/dashboard');
  } catch (err) {
    console.log(err);
  }
});
