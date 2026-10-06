import mongoose from "mongoose";

const reporteSchema = new mongoose.Schema ({
    name:{
        type : String,
        require: true,
    },
    type:{
        type:String,
        require:true,
    },
    user_id:{
        type: mongoose.Schema.Types.ObjectId, 
        ref: User
    }
}, { timestamps: true })

const Reporte = mongoose.model("Reporte", reporteSchema);

export default Reporte;