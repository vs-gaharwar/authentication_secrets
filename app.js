//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

////////////////////////////L5 Security: Passport and Session////////////////////////////////////////////

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

////////////////////////////Database connection////////////////////////////////////////////

mongoose.connect(process.env.DB_URL, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema(
  {
    email: String,
    password: String,
    googleId: String,
    secret: String
  }
);

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
userSchema.set('autoIndex', false);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secrets-incognito.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

////////////////////////////Home route////////////////////////////////////////////

app.route("/")

.get(function(req, res){
  res.render("home");
});

////////////////////////////Register route////////////////////////////////////////////

app.route("/register")

.get(function(req, res){
  res.render("register");
})

.post(function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});

////////////////////////////Secrets route////////////////////////////////////////////

app.route("/secrets")

.get(function(req, res){
  if(req.isAuthenticated()){
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
      if(err) console.log(err);
      else {
        if(foundUsers){
          res.render("secrets", {usersWithSecret: foundUsers});
        }
      }
    });
  } else {
    res.redirect("/login");
  }
});

////////////////////////////Submit route////////////////////////////////////////////

app.route("/submit")

.get(function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})

.post(function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err, foundUser){
    if(err) console.log(err);
    else {
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

////////////////////////////Google Authorization route////////////////////////////////////////////

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

////////////////////////////Login route////////////////////////////////////////////

app.route("/login")

.get(function(req, res){
  res.render("login");
})

.post(function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err) console.log(err);
    else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

////////////////////////////Logout route////////////////////////////////////////////

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});




////////////////////////////Server Start////////////////////////////////////////////

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
  console.log("Server started on port 3000");
});
