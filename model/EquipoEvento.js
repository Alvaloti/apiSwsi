import mongoose from "mongoose";
import Inventario from "./Inventario.js";
import User from "./User.js";

const equipoEventoSchema = new mongoose.Schema(
  {
    inventory_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: Inventario,
      required: true,
      index: true,
    },
    event_type: {
      type: String,
      enum: ["actualizacion", "cambio_estado"],
      required: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    changes: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    performed_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
      required: true,
    },
    event_date: {
      type: Date,
      default: Date.now,
      required: true,
    },
  },
  { timestamps: true },
);

equipoEventoSchema.index({ inventory_id: 1, event_date: -1 });

const EquipoEvento = mongoose.model("EquipoEvento", equipoEventoSchema, "equipo_eventos");

export default EquipoEvento;
