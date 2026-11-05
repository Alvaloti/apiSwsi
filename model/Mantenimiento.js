import mongoose from "mongoose";
import Inventario from "./Inventario.js";
import User from "./User.js";

const mantenimientoSchema = new mongoose.Schema(
  {
    inventory_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: Inventario,
      required: true,
      index: true,
    },
    maintenance_type: {
      type: String,
      enum: ["preventivo", "correctivo"],
      required: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
      maxlength: 2000,
    },
    provider: {
      type: String,
      trim: true,
      maxlength: 200,
      default: "",
    },
    cost: {
      type: Number,
      min: 0,
      default: 0,
    },
    maintenance_date: {
      type: Date,
      required: true,
      default: Date.now,
    },
    result: {
      type: String,
      trim: true,
      maxlength: 2000,
      default: "",
    },
    status: {
      type: String,
      enum: ["programado", "en progreso", "completado"],
      required: true,
      default: "completado",
    },
    registered_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
      required: true,
    },
  },
  { timestamps: true },
);

mantenimientoSchema.index({ inventory_id: 1, maintenance_date: -1 });

const Mantenimiento = mongoose.model("Mantenimiento", mantenimientoSchema, "mantenimientos");

export default Mantenimiento;
