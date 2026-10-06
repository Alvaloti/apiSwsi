import mongoose from "mongoose";
import User from "./User.js";
import autoIncrement from "./autoIncrement.js";

const inventarioSchema = new mongoose.Schema ({
    id: {
        type: Number,
        required: true,
        unique: true,
        immutable: true,
    },
    type:{
        type : String,
        required: true,
    },
    brand:{
        type:String,
        required:true,
    },
    model:{
        type:String,
        required:true
    },
    serial_number:{
        type:String,
        required:true,
        unique: true,
    },
    status:{
        type:String,

    },
    assigned_to:{
        type: mongoose.Schema.Types.ObjectId, 
        ref: User,
        default: null
    }
}, { timestamps: true })

autoIncrement(inventarioSchema, { field: "id", counterName: "inventario" });

const Inventario = mongoose.model("Inventario", inventarioSchema);

export default Inventario;
