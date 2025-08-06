import mongoose from "mongoose";

const connectDb=async()=>{
    await mongoose.connect(process.env.MONGODB_URI).then(()=>{
        console.log("DB Connected Successfully");
        
    }).catch(()=>{
        console.log("Error connecting DB");
        
    })
}

export default connectDb;