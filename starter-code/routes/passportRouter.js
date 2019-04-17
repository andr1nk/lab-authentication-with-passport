const express = require("express");
const passportRouter = express.Router();
const bcrypt = require("bcryptjs");
const passport = require("passport");
const User = require("../models/user")

const ensureLogin = require("connect-ensure-login");


passportRouter.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("passport/private", { user: req.user }); 
});

passportRouter.get("/signup", (req, res, next) => {
  res.render("passport/signup")
})

passportRouter.post("/signup", (req, res, next) => {
  const { username, password } = req.body;
  const salt = bcrypt.genSaltSync()
  const hashPassword = bcrypt.hashSync(password, salt)

  if (!username || !password) {
    res.render("passport/signup", {errorMessage: "You need a username and a password to register"})
  return 
  }
  User.findOne({ username })
    .then(user => {
      if (user) {
        res.render("passport/signup", {
          errorMessage: "There is already a registered user with this username"
        })
        return
      }
      User.create({ username, password: hashPassword })
        .then(() => {
          res.redirect("/")
        })
        .catch(err => {
          console.error("Error while registering new user", err)
          next()
        })
    })
    .catch(err => {
      console.error("Error while looking for user", err)
    })
})

passportRouter.get("/login", (req,res,next) => {
  res.render("passport/login", {
    errorMessage: req.flash("error")
  })
})

passportRouter.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/private-page",
    failureRedirect: "/login",
    failureFlash: true,
    passReqToCallback: true
  })
)


module.exports = passportRouter;