import mongoose from "mongoose";
import autoIncrement from "./autoIncrement.js";

const categorySchema = new mongoose.Schema({
    id: {
        type: Number,
        required: true,
        unique: true,
        immutable: true,
    },
    name:{
        type:String,
        required:true,
        unique:true
    },
    description:{
        type:String,
        required:true
    },
    applies_to: {
        type: String,
        enum: ["ambos", "solicitud", "ticket"],
        default: "ambos",
        required: true,
    },
    active:{
        type:Boolean,
        default:true
    }
}, {timestamps:true}
);

autoIncrement(categorySchema, { field: "id", counterName: "categoria" });

const Category = mongoose.model("Categoria", categorySchema);

export default Category;
