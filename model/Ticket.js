import mongoose from "mongoose";
import Adjunto from "./Adjunto.js";
import User from "./User.js";
import autoIncrement from "./autoIncrement.js";
import ESTADOS from "./Estados.js";

const ticketSchema = new mongoose.Schema(
  {
    folio: {
      type: String,
      required: true,
      unique: true,
      immutable: true,
    },
    titulo: {
      type: String,
      required: true,
    },
    descripcion: {
      type: String,
      required: true,
    },
    prioridad: {
      type: String,
      required: true,
    },
    estado: {
      type: String,
      enum: ESTADOS,
      required: true,
      default: "nuevo"
    },
    comentarios: {
      type: String,
    },
    solicitante_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
    },
    supervisor_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
    },
    tecnico_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
    },
    solucion: {
      type: String,
    },
    attached: {
      type: Object,
      ref : Adjunto
    },
    fecha_cierre: {
      type: Date,
    },
  },
  { timestamps: true },
);

ticketSchema.index({ tecnico_id: 1, createdAt: -1 });

autoIncrement(ticketSchema, { field: "folio", counterName: "ticket" });

const Ticket = mongoose.model("Ticket", ticketSchema);

export default Ticket;
