import mongoose from 'mongoose';


const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    isPremium: { type: Boolean, default: false },
  },
  { timestamps: true }
);

const userModel = mongoose.model('User', userSchema);
export default userModel;
