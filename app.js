//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const bcrypt = require('bcrypt');
//const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
 
const port = process.env.PORT || 3000;
 
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser:true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

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
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Setup passport for Facebook OAuth Strategy
passport.use(
    new FacebookStrategy(
        {
            clientID: process.env.FB_ID,
            clientSecret: process.env.FB_SECRET,
            callbackURL: "http://localhost:3000/auth/facebook/secrets"
        },
        function(accessToken, refreshToken, profile, cb) {
            User.findOrCreate({ facebookId: profile.id }, function(err, user) {
                return cb(err, user);
            });
        }
    )
);

app.get('/', (req, res) => {
    res.render('home');
  });

app.get("/auth/google", passport.authenticate("google", {scope: ["profile"]}));  

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  app.route('/login')
  .get((req, res) => {
    res.render('login');
  })
  .post((req, res) => {
     const user = new User({
        username: req.body.username,
        password: req.body.password
     }); 
    req.login(user, (err) => {
        if(err){
            console.log(err);
            res.redirect("/login"); 
        }else{
            passport.authenticate("local")(req, res, ()=> {
            res.redirect("/secrets");
            });
        }
    });
  }) 

  app.get("/secrets",(req, res) => { 
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
      if (err){
        console.log(err);
      } else {
        if (foundUsers) {
          console.log(req.user.id);
          res.render("secrets", {usersWithSecrets: foundUsers});
        }
      }
    });
  });

  app.get("/logout", (req, res)=> {
    req.logout();
    res.redirect("/");
  });

  app.route('/register')
  .get((req, res) => {
    res.render('register');
  })
  .post((req, res) => {
    User.register({username: req.body.username}, req.body.password, (err, user) =>{
        if(err){
            console.log(err); 
            res.redirect("/register");       
        }else{
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });           
        }
    });
  });

  app.route("/submit")
  .get((req, res)=> {
    validateUser("submit", req, res);
  })
  .post((req, res)=>{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, (err, foundUser)=> {
      if(err){
        console.log(err);       
      }else{
        foundUser.secret = submittedSecret;
        foundUser.save(()=>{
          res.redirect("/secrets");
        })
      }
    })
  });


  function validateUser(route, req, res){
    if(req.isAuthenticated()){
      res.render(route);
  }else{
      res.redirect("/login"); 
  }
  }

app.listen(port, () => console.log(`Server started at port: ${port}`)
);