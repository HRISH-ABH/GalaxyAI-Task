import express from "express";
const routes=express.Router();

import * as authController from "../controllers/auth.controller.js";
routes.post("/register", authController.registerController);
routes.post("/login", authController.loginController);
routes.post("/logout", authController.logOutController);
export default routes;