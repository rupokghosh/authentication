/////// app.js
const bcrypt = require("bcryptjs");
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const mongoDb =
  "mongodb+srv://rupokghosh291:Pineapple%23123@cluster0.vhv9vf9.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
mongoose.connect(mongoDb);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});

app.listen(3000, () => console.log("app listening on port 3000!"));

// route handlers

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
  try {
    // Hash the password using bcrypt
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) {
        throw err; // Throw error if bcrypt hash fails
      }

      // Create a new user instance with the hashed password
      const user = new User({
        username: req.body.username,
        password: hashedPassword, // Store hashed password in the database
      });

      // Save the user to the database
      const result = await user.save();

      // Redirect the user after successful signup
      res.redirect("/");
    });
  } catch (err) {
    // Handle errors
    return next(err);
  }
});

// current User

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

// setup local strategy

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      const match = await bcrypt.compare(password, user.password);
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      if (!match) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// serialize and deserialize

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

// log-in

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

// log-out

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
