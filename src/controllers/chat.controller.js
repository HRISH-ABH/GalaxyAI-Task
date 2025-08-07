import chatModel from "../models/chat.model.js";
import userModel from "../models/user.model.js";
import genAI from "../service/gemini.service.js";

const getModelsController = (req, res) => {
  const allModels = [
    {
      id: "gemini-2.5-flash",
      name: "Gemini Flash",
      description: "Audio, images, videos, and text",
      premium: false,
    },
    {
      id: "gemini-2.5-pro",
      name: "Gemini Pro",
      description: "Audio, images, videos, text, and PDF",
      premium: false,
    },
  ];

  console.log(req.user.isPremium);

  const available = allModels.filter(
    (model) => !model.premium || req.user.isPremium
  );

  res.json({
    models: available,
    isPremium: req.user.isPremium,
  });
};

const createChatController = async (req, res) => {
  const { title = "New Chat", model = "gemini-pro" } = req.body;

  const chat = await chatModel.create({
    userId: req.user._id,
    title,
    model,
    messages: [],
  });

  res.status(201).json(chat);
};
const sendMessageController = async (req, res) => {
  const { message, attachments = [] } = req.body;

  const chat = await chatModel.findOne({
    _id: req.params.id,
    userId: req.user._id,
  });
  if (!chat) return res.status(404).json({ message: "Chat not found" });

  const userMessage = {
    role: "user",
    content: message,
    attachments,
    timestamp: new Date(),
  };
  chat.messages.push(userMessage);

  const history = chat.messages.map((msg) => {
    const parts = [];

    if (msg.attachments && msg.attachments.length > 0) {
      msg.attachments.forEach((url) => {
        parts.push({
          inline_data: {
            mime_type: "image/jpeg",
            data: url,
          },
        });
      });
    }

    parts.push({ text: msg.content });
    return { role: msg.role, parts };
  });

  const result = await genAI.models.generateContent({
    model: chat.model,
    contents: history,
  });

  const aiResponse = result.text;

  const assistantMessage = {
    role: "assistant",
    content: aiResponse,
    timestamp: new Date(),
  };
  chat.messages.push(assistantMessage);

  if (chat.messages.length === 2) {
    chat.title = message.length > 50 ? message.slice(0, 50) + "..." : message;
  }

  await chat.save();

  res.json({ userMessage, assistantMessage, chat });
};

const getChatsController = async (req, res) => {
  try {
    const chats = await chatModel
      .find({
        userId: req.user._id,
        isActive: true,
      })
      .sort({ updatedAt: -1 });

    res.json({
      chats,
    });
  } catch (e) {
    res.status(500).json({
      message: e.message,
    });
  }
};

const getChatByIdController = async (req, res) => {
  try {
    const chatId = req.params.id;

    const chat = await chatModel.findOne({
      _id: chatId,
      userId: req.user._id,
      isActive: true,
    });

    if (!chat) {
      return res.status(404).json({ message: "Chat not found" });
    }

    res.status(200).json(chat);
  } catch (error) {
    console.error("Error fetching chat by ID:", error.message);
    res
      .status(500)
      .json({ message: "Something went wrong while fetching the chat" });
  }
};

const deleteChatController = async (req, res) => {
  try {
    const chatId = req.params.id;

    const chat = await chatModel.findOneAndUpdate(
      { _id: chatId, userId: req.user._id, isActive: true },
      { isActive: false },
      { new: true }
    );

    if (!chat) {
      return res.status(404).json({ message: "Chat not found" });
    }

    res.status(200).json({ message: "Chat deleted successfully", chat });
  } catch (error) {
    console.error("Error deleting chat:", error.message);
    res
      .status(500)
      .json({ message: "Something went wrong while deleting the chat" });
  }
};

export {
  getModelsController,
  createChatController,
  sendMessageController,
  getChatsController,
  getChatByIdController,
  deleteChatController,
};
