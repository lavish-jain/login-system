if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const express = require("express");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const method_override = require("method-override");
const initialize_passport = require("./passport_config");
const app = express();

initialize_passport(
  passport,
  (email) => users.find((user) => user.email === email),
  (id) => users.find((user) => user.id === id)
);
// storing users. ideally should store in db
const users = [];
app.use(express.urlencoded({ extended: false }));
app.set("view-engine", "ejs");
app.use(flash());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(method_override("_method"));

const check_authentication = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
};

const check_not_authenticated = (req, res, next) => {
  if (req.isAuthenticated()) return res.redirect("/");
  return next();
};

app.get("/", check_authentication, (req, res) => {
  res.render("index.ejs", { name: req.user.name });
});

app.get("/login", check_not_authenticated, (req, res) => {
  res.render("login.ejs");
});

app.get("/register", check_not_authenticated, (req, res) => {
  res.render("register.ejs");
});

app.post("/register", check_not_authenticated, async (req, res) => {
  try {
    const password_hash = await bcrypt.hash(req.body.password, 10);
    users.push({
      id: Date.now().toString(),
      name: req.body.name,
      email: req.body.email,
      password: password_hash,
    });
    res.redirect("/login");
  } catch (err) {
    console.log("error registering: ", err);
    res.redirect("/register");
  }
});
app.post(
  "/login",
  check_not_authenticated,
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.delete("/logout", (req, res) => {
  req.logOut();
  res.redirect("/login");
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
