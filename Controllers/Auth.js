const crypto = require("crypto");
const { User } = require("../models/Auth");
const jwt = require("jsonwebtoken");
const { sentizeuser } = require("../Commen");
require("dotenv").config();
const SECRET_KEY = process.env.SECRET_KEY;
//API used to create new User With Unquie Phone NUmber
exports.CreateAccount = async (req, res) => {
  const user = await User.findOne({ Phone_Number: req.body.Phone_Number });
  if (user) {
    res.status(301).json({ error: "User Already Exist" });
    return;
  }
  try {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      31000,
      32,
      "sha256",
      async function (err, hashedpassword) {
        const newuser = new User({
          username: req.body.username,
          Phone_Number: req.body.Phone_Number,
          hash: hashedpassword,
          salt,
        });
        const doc = await newuser.save();
        const token = jwt.sign(sentizeuser(doc), SECRET_KEY);
        res
          .cookie("jwt", token, {
            expires: new Date(Date.now() + 3600000),
            httpOnly: true,
          })
          .status(200)
          .json({ username: doc.username, Phone_Number: doc.Phone_Number });
      }
    );
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

// API used to Login User

exports.LoginUser = async (req, res) => {
 
  res.cookie('jwt' ,req.user.token,{
    expires: new Date(Date.now() + 600000),
    httpOnly:true,
  }).status(200).json({message:"Login SuceesFuly"})
 
};

//API To check User EXistence

exports.CheckUser = async (req, res) => {
 
  if (req.user) {
    res.json(req.user);
  } else {
    res.status(401)
  }
};

//API to Update Password

exports.UpdatePassword = async (req, res) => {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(req.body.password, salt, 10000, 512, "sha512");
  const user = await User.findOneAndUpdate(
    { Phone_Number: req.body.Phone_Number },
    { hash: hash }
  );
  res
    .status(200)
    .json({ message: "Password Updated", username: user.username });
};
