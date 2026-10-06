import mongoose from "mongoose";
import autoIncrement from "./autoIncrement.js";

const areaSchema = new mongoose.Schema({
    id:{
        type:Number,
        required:true,
        unique:true,
        immutable:true
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
    active:{
        type:Boolean,
        default:true
    }
}, {timestamps:true}
);

autoIncrement(areaSchema, { field: "id", counterName: "area" });

const Area = mongoose.model("Area", areaSchema);

export default Area;
