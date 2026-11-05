import mongoose from "mongoose";
import User from "./User.js";
import autoIncrement from "./autoIncrement.js";

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
      trim: true,
      maxlength: 4000,
    },
    solucion_por: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
    },
    fecha_solucion: {
      type: Date,
    },
    escalamientos: [{
      motivo: {
        type: String,
        required: true,
        trim: true,
        maxlength: 2000,
      },
      tecnico_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: User,
        required: true,
      },
      fecha: {
        type: Date,
        default: Date.now,
      },
    }],
    encuesta: {
      calificacion: {
        type: Number,
        min: 1,
        max: 5,
      },
      comentario: {
        type: String,
        trim: true,
        maxlength: 2000,
      },
      fecha: Date,
    },
    fecha_cierre: {
      type: Date,
    },
    sla_response_due: Date,
    sla_resolution_due: Date,
    sla_warning_at: Date,
    first_response_at: Date,
  },
  { timestamps: true },
);

ticketSchema.index({ tecnico_id: 1, createdAt: -1 });

autoIncrement(ticketSchema, { field: "folio", counterName: "ticket" });

const Ticket = mongoose.model("Ticket", ticketSchema);

export default Ticket;
