import express from "express";
import authMiddleware from "../middlewares/auth.middleware.js";
import { getModelsController ,createChatController ,sendMessageController, getChatsController,getChatByIdController,deleteChatController} from "../controllers/chat.controller.js";
const routes = express.Router();

routes.use(authMiddleware);

routes.get("/models", getModelsController);

routes.post("/", createChatController);

routes.get("/", getChatsController);

routes.get("/:id", getChatByIdController);

routes.post("/:id/message", sendMessageController);

routes.delete("/:id", deleteChatController);

export default routes;
