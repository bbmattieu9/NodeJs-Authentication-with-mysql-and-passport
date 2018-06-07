var express = require('express');
var router = express.Router();


var expressValidator = require('express-validator');
var passport = require('passport');

var bcrypt = require('bcrypt');
const saltRounds = 10;

/* GET home page. */
router.get('/', function(req, res) {
  //console.log(req.user +" na me");
  console.log(req.isAuthenticated());
  res.render('home', {
    title: 'Home'
  });
});

// router.get('/welcome', function(req, res) {
//   console.log(req.user);
//   console.log(req.isAuthenticated());
//   res.render('welcome', {
//     title: 'Welcome'
//   });
// });

//Route that will open register form
router.get('/register', function(req, res, next) {
  res.render('register', {
    title: 'Sign Up'
  });
});

//login Route to display login form
router.get('/login', function(req, res) {
  res.render('login', {
    title: 'Login'
  });
});

//Route for login in via Passport
router.post('/login', passport.authenticate('local', {
  successRedirect: '/profile',
  failureRedirect: '/login'
}));

//Profile Route
router.get('/profile', authenticationMiddleware(), function(req, res) {
  var user = new Object();
  user = req.user;
  //console.log("profile: "+user[0]['fullname']);
  //console.log(req.isAuthenticated());
  res.render('profile', {
    title: 'Profile',
    user: user[0]
  });
});

//Route that will enable logout & destroy session
router.get('/logout', function(req, res) {
  req.logout();
  req.session.destroy();
  res.redirect('/');
});


//Remove dis Route later...just for testing purpose
router.get('/contact', function(req, res, next) {
  res.render('contact', {
    title: 'Contact Me'
  });
});

//Route to process form submission, database insert
router.post('/register', function(req, res, next) {

  //Use express validator to validate input fields..
  req.checkBody('fullname', 'Name field cannot be empty').notEmpty();
  req.checkBody('fullname', 'Full name must be between 4-100 characters long.').len(4, 100);
  req.checkBody('username', 'Username field cannot be empty').notEmpty();
  req.checkBody('username', 'Username must be between 4-15 characters long.').len(4, 15);
  req.checkBody('email', 'Please enter a valid email').isEmail();
  req.checkBody('email', 'Email must be between 4-15 characters long.').len(4, 50);
  req.checkBody('password', 'Password must be between 4-15 characters long.').len(4, 15);
  req.checkBody('password', 'Password must include one lowercase character, one uppercase character and a special character.').matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i");
  req.checkBody('passwordMatch', 'Password must be between 8-100 characters long.').len(8, 100);
  req.checkBody('passwordMatch', 'Passwords do not match.').equals(req.body.password);

  //Grab the list of errors from the validation above
  const errors = req.validationErrors();
  if (errors) {
    console.log(`errors: ${JSON.stringify(errors)}`);
    res.render('register', {
      title: 'Registration Error',
      errors: errors
    });
  } else {
    //Assign validated data to constants before sending it to the Database
    const fullname = req.body.fullname;
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    //Call for the Database connection File..
    const db = require('../db.js');

    bcrypt.hash(password, saltRounds, function(err, hash) {

      //Insert the Data into the Database...
      db.query('INSERT INTO users (fullname, username, email, password) VALUES (?,?,?,?)', [fullname, username, email, hash], function(err, results, fields) {
        if (err) throw err;

        db.query('SELECT LAST_INSERT_ID() as user_id', function(error, results, field) {
          if (error) throw error;

          const user_id = results[0];
          //console.log(results[0]);
          req.login(user_id, function(err) {
            res.redirect('/profile'); //can redirect them to the welcome page before heading to the profile page
          });

        });
      });

    });
  }
});

passport.serializeUser(function(user_id, done) {
  done(null, user_id);
});

passport.deserializeUser(function(user_id, done) {
  //maybe i should run a query to grab the user data here
//  console.log("this must be object" + user_id['user_id']);
  const db = require('../db.js');
  db.query('SELECT * FROM users WHERE id =' + user_id['user_id'], function(err, rows) {
    //console.log(rows);
    if (err) throw err;
    done(null, rows);

  });
});


function authenticationMiddleware() {
  return (req, res, next) => {
    //console.log(`req.session.passport.user: ${JSON.stringify(req.session.passport)}`);
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
  }
}

module.exports = router;
