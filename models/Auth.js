const mongoose = require('mongoose');

const Userschema = new mongoose.Schema({
   username:{type:String, unique:true, required:[true, "User Name is Required"]},
   Phone_Number:{type:String,  unique:true ,required:[true,"Phone Number is required"]},
   salt:Buffer,
   hash:Buffer,
   Address:mongoose.Schema.Types.ObjectId,
   cart:mongoose.Schema.Types.ObjectId,
   orders:mongoose.Schema.Types.ObjectId
},{timestamps:true});

exports.User = mongoose.model('User', Userschema)