import mongoose from "mongoose";

const catalogoSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["estado", "prioridad"],
      required: true,
      index: true,
    },
    key: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      maxlength: 50,
    },
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 80,
    },
    description: {
      type: String,
      trim: true,
      maxlength: 300,
      default: "",
    },
    applies_to: {
      type: String,
      enum: ["ambos", "solicitud", "ticket"],
      required: true,
      default: "ambos",
      index: true,
    },
    order: {
      type: Number,
      min: 0,
      max: 999,
      default: 0,
    },
    active: {
      type: Boolean,
      default: true,
      index: true,
    },
    system: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true },
);

catalogoSchema.index({ type: 1, key: 1 }, { unique: true });
catalogoSchema.index({ type: 1, active: 1, order: 1 });

export default mongoose.model("Catalogo", catalogoSchema, "catalogos");
