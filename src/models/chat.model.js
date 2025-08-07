import mongoose from "mongoose";

const messageSchema = new mongoose.Schema({
  role: { type: String, enum: ['user', 'assistant'], required: true },
  content: { type: String, required: true },
  attachments: [
    {
      type: { type: String, enum: ['image', 'file'] },
      url: String,
      filename: String,
    },
  ],
  timestamp: { type: Date, default: Date.now },
});

const chatSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    model: { type: String, default: 'gemini-flash' },
    messages: [messageSchema],
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

const chatModel= mongoose.model('Chat', chatSchema);
export default chatModel;