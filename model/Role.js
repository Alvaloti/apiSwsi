import mongoose from "mongoose";
import autoIncrement from "./autoIncrement.js";

const roleSchema = new mongoose.Schema({
  id: {
    type: Number,
    required: true,
    unique: true,
    immutable: true,
  },
  name: {
    type: String,
    required: true,
    unique: true,
  },
  description: {
    type: String,
  },
  active: {
    type: Boolean,
    default: true,
  },
  permissions: [
    {
      type: String,
    },
  ],
}, {timestamps:true});

autoIncrement(roleSchema, { field: "id", counterName: "role" });

const Role = mongoose.model("Role", roleSchema, "roles");

export default Role;
