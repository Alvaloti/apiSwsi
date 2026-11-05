import mongoose from "mongoose";
import User from "./User.js";
import Area from "./Area.js";
import Category from "./Categoria.js";
import autoIncrement from "./autoIncrement.js";

const solicitudSchema = new mongoose.Schema(
  {
    folio: {
      type: String,
      required: true,
      unique: true,
      immutable: true,
    },
    tipo: {
      type: String,
      required: true,
    },
    category_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: Category,
      default: null,
    },
    descripcion: {
      type: String,
      required: true,
    },
    area: {
      type: mongoose.Schema.Types.ObjectId,
      ref: Area,
    },
    prioridad: {
      type: String,
      required: true,
    },
    estado: {
      type: String,
      required: true,
      default: "nuevo",
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
    estado_aprobacion: {
      type: String,
      enum: ["pendiente", "aprobada", "rechazada"],
      required: true,
      default: "pendiente",
      index: true,
    },
    fecha_revision: {
      type: Date,
    },
    motivo_rechazo: {
      type: String,
      trim: true,
      maxlength: 1000,
    },
    tecnico_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
    },
    fecha_aprobacion: {
      type: Date,
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

solicitudSchema.index({ tecnico_id: 1, createdAt: -1 });
solicitudSchema.index({ estado_aprobacion: 1, createdAt: -1 });

autoIncrement(solicitudSchema, { field: "folio", counterName: "solicitud" });

const Solicitud = mongoose.model("Solicitud", solicitudSchema, "solicitud");

export default Solicitud;
