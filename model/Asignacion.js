import mongoose from "mongoose";
import Inventario from "./Inventario.js";
import User from "./User.js";

const asignacionSchema = new mongoose.Schema(
  {
    inventory_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: Inventario,
      required: true,
    },
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
      required: true,
    },
    assigned_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
      required: true,
    },
    assigned_at: {
      type: Date,
      default: Date.now,
      required: true,
    },
    returned_at: Date,
    notes: {
      type: String,
      trim: true,
      default: "",
    },
    return_notes: {
      type: String,
      trim: true,
      default: "",
    },
    active: {
      type: Boolean,
      default: true,
      required: true,
    },
  },
  { timestamps: true },
);

asignacionSchema.index(
  { inventory_id: 1, active: 1 },
  { unique: true, partialFilterExpression: { active: true } },
);
asignacionSchema.index({ user_id: 1, assigned_at: -1 });

const Asignacion = mongoose.model("Asignacion", asignacionSchema);

export default Asignacion;
