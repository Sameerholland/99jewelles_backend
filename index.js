const exprss = require('express');
const mongoose = require('mongoose')
const cors = require('cors')
require('dotenv').config();
const server = exprss();

const Authrouter = require('./Routes/Auth')
const  session = require('express-session');
const passport = require('passport');
const { User } = require('./models/Auth');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto')
const jwt = require('jsonwebtoken');
const { sentizeuser } = require('./Commen');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const port = process.env.PORT;
const SECRET_KEY = process.env.SECRET_KEY;

var opts = {}
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = SECRET_KEY;


server.use(session({
   secret: 'keyboard cat',
   resave: false,
   saveUninitialized: true,
   cookie: { secure: false, maxAge:600000}
 }))
 server.use(exprss.json())
 server.use(cors());
 server.use('/Auth', Authrouter.router)




 passport.use('local' , new LocalStrategy({usernameField:"Phone_Number"},
   async function(Phone_Number, password, done) {
     try {
      console.log('Working')
      const user = await User.findOne({Phone_Number:Phone_Number});
      console.log('Working')
      if(!user){
         return done(null , false ,{error:"User Not Exist"})
      }
      crypto.pbkdf2(password, user.salt, 31000,32,'sha256', async function (err,hash){
         if(!crypto.timingSafeEqual(user.hash,hash)){
            return done(null,false, {error:"Wrong Password "})
         }
         console.log('Working')
         const token = jwt.sign(sentizeuser(user),SECRET_KEY)
         done(null,{username:user.username,Phone_Number:user.Phone_Number,token})
      })
     }
     catch (err){
      done(err)
     }
   }
 ));

 passport.use('jwt' ,new JwtStrategy(opts,async function(jwt_payload, done) {
   try {
      const user = await User.findOne({Phone_Number:jwt_payload.Phone_Number});
      if(user){
         return done(null, sentizeuser(user))
      }
      else {
         return done(null ,false ,{error:"Something Went Wrong"})
      }
   }
   catch (err){
      done(err)
   }
}));

 passport.serializeUser(function(user, cb) {
   console.log('Serialzier stated')
   process.nextTick(function() {
    return cb(null, { username: user.username ,Phone_Number:user.Phone_Number });
   });
 });
 
 passport.deserializeUser(function(user, cb) {
   process.nextTick(function() {
     return cb(null, user);
   });
 });


main().catch((err) => {console.log(err)})
async function main(){
   await mongoose.connect('mongodb+srv://<MONGODB USERNAME>:<MONGODB PASSWORD>@cluster0.hdczzkg.mongodb.net/?retryWrites=true&w=majority')
   console.log('Database Connected')
}
server.listen(port,()=>{
   console.log('Server Started')
})
