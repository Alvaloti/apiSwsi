import mongoose from "mongoose";

const attachedSchema = new mongoose.Schema({
    solicitud_id:{
        type: mongoose.Schema.Types.ObjectId, 
        ref: "Solicitud"
    },
    ticket_id:{
        type: mongoose.Schema.Types.ObjectId, 
        ref: "Ticket"
    },
    name:{
        type:String,
    },
    url:{
        type:String
    },
    ext:{
        type:String
    }
}, {timestamps:true}
);

const Adjunto = mongoose.model('Adjunto', attachedSchema);

export default Adjunto;
