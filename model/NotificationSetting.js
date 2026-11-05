import mongoose from "mongoose";

const notificationSettingSchema = new mongoose.Schema({
  key: { type: String, default: "global", unique: true, immutable: true },
  events: {
    assignment: { type: Boolean, default: true },
    status: { type: Boolean, default: true },
    decision: { type: Boolean, default: true },
    solution: { type: Boolean, default: true },
    escalation: { type: Boolean, default: true },
    closure: { type: Boolean, default: true },
    sla_warning: { type: Boolean, default: true },
    sla_breach: { type: Boolean, default: true },
  },
  allow_user_preferences: { type: Boolean, default: true },
  polling_seconds: { type: Number, min: 15, max: 300, default: 30 },
  retention_days: { type: Number, min: 7, max: 730, default: 90 },
  updated_by: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
}, { timestamps: true });

export default mongoose.model("NotificationSetting", notificationSettingSchema, "notification_settings");
