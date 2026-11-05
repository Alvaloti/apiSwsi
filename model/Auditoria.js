import mongoose from "mongoose";
import User from "./User.js";

const auditoriaSchema = new mongoose.Schema(
  {
    category: {
      type: String,
      enum: ["acceso", "operacion", "seguridad"],
      required: true,
      index: true,
    },
    action: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
      default: null,
      index: true,
    },
    user_email: {
      type: String,
      trim: true,
      lowercase: true,
      default: "",
    },
    method: {
      type: String,
      default: "",
    },
    path: {
      type: String,
      required: true,
      trim: true,
    },
    resource: {
      type: String,
      default: "",
      trim: true,
    },
    resource_id: {
      type: String,
      default: "",
      trim: true,
    },
    success: {
      type: Boolean,
      required: true,
      index: true,
    },
    status_code: {
      type: Number,
      required: true,
    },
    ip: {
      type: String,
      default: "",
    },
    user_agent: {
      type: String,
      default: "",
      maxlength: 1000,
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    occurred_at: {
      type: Date,
      default: Date.now,
      required: true,
      index: true,
    },
  },
  { timestamps: true },
);

auditoriaSchema.index({ occurred_at: -1, category: 1 });
auditoriaSchema.index({ user_email: 1, occurred_at: -1 });

const Auditoria = mongoose.model("Auditoria", auditoriaSchema, "auditoria");

export default Auditoria;
