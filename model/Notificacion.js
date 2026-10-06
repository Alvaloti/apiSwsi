import mongoose from "mongoose";

const notificacionSchema = new mongoose.Schema ({
    user_id:{
        type: mongoose.Schema.Types.ObjectId, 
        ref: User
    },
    message:{
        type : String,
        require: true,
    }
}, { timestamps: true })

const Notificacion = mongoose.model("Notificacion", notificacionSchema);

export default Notificacion;