import mongoose from "mongoose";

const notificationSchema = new mongoose.Schema(
  {
    recipient: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    type: {
      type: String,
      enum: ["assignment", "status", "decision", "solution", "escalation", "closure", "sla_warning", "sla_breach"],
      required: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    message: {
      type: String,
      required: true,
      trim: true,
    },
    entity_type: {
      type: String,
      enum: ["solicitud", "ticket"],
      required: true,
    },
    entity_id: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
    },
    read_at: {
      type: Date,
      default: null,
    },
    unique_key: {
      type: String,
    },
  },
  { timestamps: true },
);

notificationSchema.index({ recipient: 1, read_at: 1, createdAt: -1 });
notificationSchema.index({ unique_key: 1 }, { unique: true, partialFilterExpression: { unique_key: { $type: "string" } } });

const Notificacion = mongoose.model("Notificacion", notificationSchema, "notificaciones");

export default Notificacion;
