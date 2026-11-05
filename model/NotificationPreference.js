import mongoose from "mongoose";

const preferenceSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, unique: true },
  assignment: { type: Boolean, default: true },
  status: { type: Boolean, default: true },
  decision: { type: Boolean, default: true },
  solution: { type: Boolean, default: true },
  escalation: { type: Boolean, default: true },
  closure: { type: Boolean, default: true },
  sla_warning: { type: Boolean, default: true },
  sla_breach: { type: Boolean, default: true },
}, { timestamps: true });

export default mongoose.model("NotificationPreference", preferenceSchema, "notification_preferences");
