import mongoose from "mongoose";

const systemSettingSchema = new mongoose.Schema({
  key: { type: String, default: "general", unique: true, immutable: true },
  system_name: { type: String, trim: true, maxlength: 100, default: "SWSI" },
  organization_name: { type: String, trim: true, maxlength: 150, default: "" },
  support_email: { type: String, trim: true, lowercase: true, maxlength: 150, default: "" },
  timezone: { type: String, enum: ["America/Mexico_City", "America/Cancun", "America/Tijuana", "UTC"], default: "America/Mexico_City" },
  date_format: { type: String, enum: ["dd/MM/yyyy", "MM/dd/yyyy", "yyyy-MM-dd"], default: "dd/MM/yyyy" },
  default_page_size: { type: Number, enum: [5, 10, 25, 50, 100], default: 10 },
  max_attachment_mb: { type: Number, min: 1, max: 25, default: 10 },
  session_duration_minutes: { type: Number, min: 15, max: 1440, default: 60 },
  maintenance_mode: { type: Boolean, default: false },
  maintenance_message: { type: String, trim: true, maxlength: 500, default: "El sistema se encuentra temporalmente en mantenimiento." },
  updated_by: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
}, { timestamps: true });

export default mongoose.model("SystemSetting", systemSettingSchema, "system_settings");
