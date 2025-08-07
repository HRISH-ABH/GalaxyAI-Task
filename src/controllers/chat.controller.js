import chatModel from "../models/chat.model.js";
import userModel from "../models/user.model.js";
import genAI from "../service/gemini.service.js";



const getModelsController = (req, res) => {
  const allModels = [
    { id: 'gemini-2.5-flash', name: 'Gemini Flash', description: 'Audio, images, videos, and text', premium: false },
    { id: 'gemini-2.5-pro', name: 'Gemini Pro', description: 'Audio, images, videos, text, and PDF', premium: false }
  ];

  console.log(req.user.isPremium);
  
  const available = allModels.filter(model => !model.premium || req.user.isPremium);

  res.json({
    models: available,
    isPremium: req.user.isPremium
  });
};

const createChatController = async (req, res) => {
  const { title = 'New Chat', model = 'gemini-pro' } = req.body;

 const chat=await chatModel.create({
    userId: req.user._id,
    title,
    model,
    messages: []
  });

  res.status(201).json(chat);
};
const sendMessageController = async (req, res) => {
  const { message, attachments = [] } = req.body;

  const chat = await chatModel.findOne({ _id: req.params.id, userId: req.user._id });
  if (!chat) return res.status(404).json({ message: 'Chat not found' });
 

 
  const userMessage = {
    role: 'user',
    content: message,
    attachments,
    timestamp: new Date(),
  };
  chat.messages.push(userMessage);


    const history = chat.messages.map(msg => ({
      role: msg.role,
      parts: [{ text: msg.content }],
    }));


const result=await genAI.models.generateContent({
    model: chat.model,
    contents: history,
  });

    const aiResponse = result.text;

    // 6. Create and push the assistant's message
    const assistantMessage = {
      role: 'assistant',
      content: aiResponse,
      timestamp: new Date(),
    };
    chat.messages.push(assistantMessage);

    // 7. Auto-generate chat title on first message
    if (chat.messages.length === 2) {
      chat.title = message.length > 50 ? message.slice(0, 50) + '...' : message;
    }

    // 8. Save the updated chat
    await chat.save();

    // 9. Return the full response
    res.json({ userMessage, assistantMessage, chat });


}

export{
getModelsController,
createChatController,
sendMessageController
}
