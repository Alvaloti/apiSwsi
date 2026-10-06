import mongoose from "mongoose";

const logSchema = new mongoose.Schema(
  {
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: User,
    },
    action: {
      type: String,
      require: true,
    },
    module:{
        type:String,
        require:true
    },
    detail:{
        type:Object,

    }
  },
  { timestamps: true },
);
