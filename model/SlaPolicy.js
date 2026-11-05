import mongoose from "mongoose";

const slaPolicySchema = new mongoose.Schema({
  priority: { type: String, required: true, unique: true, lowercase: true, trim: true },
  response_hours: { type: Number, required: true, min: 0.25, max: 8760 },
  resolution_hours: { type: Number, required: true, min: 0.25, max: 8760 },
  warning_percent: { type: Number, required: true, min: 1, max: 99, default: 80 },
  active: { type: Boolean, default: true },
}, { timestamps: true });

export default mongoose.model("SlaPolicy", slaPolicySchema, "sla_policies");
