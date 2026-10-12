import mongoose from "mongoose";

const attachedSchema = new mongoose.Schema(
  {
    solicitud_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Solicitud",
      default: null,
    },
    ticket_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Ticket",
      default: null,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    mime_type: {
      type: String,
      required: true,
    },
    ext: {
      type: String,
      required: true,
      lowercase: true,
    },
    size: {
      type: Number,
      required: true,
      min: 1,
      max: 10 * 1024 * 1024,
    },
    data: {
      type: Buffer,
      required: true,
      select: false,
    },
    uploaded_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true },
);

attachedSchema.pre("validate", function () {
  const parents = [this.solicitud_id, this.ticket_id].filter(Boolean);
  if (parents.length !== 1) {
    this.invalidate(
      "solicitud_id",
      "El adjunto debe pertenecer exclusivamente a una solicitud o a un ticket",
    );
  }
});

attachedSchema.index({ solicitud_id: 1, createdAt: -1 });
attachedSchema.index({ ticket_id: 1, createdAt: -1 });

const Adjunto = mongoose.model("Adjunto", attachedSchema, "adjuntos");

export default Adjunto;
