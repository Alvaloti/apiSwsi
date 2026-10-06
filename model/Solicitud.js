import mongoose from "mongoose";
import User from "./User.js";
import Area from "./Area.js";
import autoIncrement from "./autoIncrement.js";
import ESTADOS from "./Estados.js";

const solicitudSchema = new mongoose.Schema ({
    folio: {
        type: String,
        required: true,
        unique: true,
        immutable: true,
    },
    tipo:{
        type : String,
        required: true,
    },
    descripcion:{
        type:String,
        required:true,
    },
    area:{
        type: mongoose.Schema.Types.ObjectId, 
        ref: Area
    },
    prioridad:{
        type:String,
        required:true,
    },
    estado:{
        type:String,
        enum: ESTADOS,
        required: true,
        default:"nuevo"
    },
    comentarios:{
        type:String,

    },
    solicitante_id:{
        type: mongoose.Schema.Types.ObjectId, 
        ref: User
    },
    supervisor_id:{
        type: mongoose.Schema.Types.ObjectId, 
        ref: User
    },
    tecnico_id:{
        type: mongoose.Schema.Types.ObjectId, 
        ref: User
    },
    attach:{
        type:Object,
        
    },
    fecha_aprobacion:{
        type: Date,
    },
    fecha_cierre:{
        type: Date,
    }
}, { timestamps: true })

solicitudSchema.index({ tecnico_id: 1, createdAt: -1 });

autoIncrement(solicitudSchema, { field: "folio", counterName: "solicitud" });

const Solicitud = mongoose.model("Solicitud", solicitudSchema, "solicitud");

export default Solicitud;
