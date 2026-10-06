import mongoose from "mongoose";
import Role from "./Role.js";
import Area from "./Area.js";
import autoIncrement from "./autoIncrement.js";

const userDetailsSchema = new mongoose.Schema({
  id: {
    type: Number,
    required: true,
    immutable: true,
    index: {
      unique: true,
      partialFilterExpression: { id: { $type: "number" } },
    },
  },
  username: {
    type: String,
    required: true,
    unique: true,
  },
  nomina: {
    type: Number,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true,
    unique: true,
  },
  password: {
    type: String,
    minlength: 8,
    required: true,
  },
  name:{
    type: String,
    required: true,
  },
  last_name:{
    type: String,
    required: true,
  },
  rolId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: Role,
    required: true 
  },
  area:{
    type: mongoose.Schema.Types.ObjectId, 
    ref: Area, 
    required: true 
  },
  active:{
    type:Boolean,
    default:true
  },
}, { timestamps: true });

autoIncrement(userDetailsSchema, { field: "id", counterName: "user" });

const User = mongoose.model("User", userDetailsSchema);

export default User;
