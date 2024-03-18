const express = require('express');
const {CreateAccount, LoginUser, CheckUser, UpdatePassword} = require('../Controllers/Auth')
const router = express.Router();

const passport = require('passport')
router.post('/createuser', CreateAccount)
      .post('/login',passport.authenticate('local'),LoginUser)
      .post('/check',passport.authenticate('jwt'),CheckUser)
      .post('/updatepassword',UpdatePassword)

exports.router = router;