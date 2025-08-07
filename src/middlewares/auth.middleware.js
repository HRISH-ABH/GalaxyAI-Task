import jwt from "jsonwebtoken";
import userModel from "../models/user.model.js";

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        message: "Invalid Token!",
      });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await userModel.findOne({ id: decoded._id });
    console.log(user);
    if (!user) {
      return res.status(401).json({ message: "User not found!" });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(501).json({
      message: "Unauthorized!!",
    });
  }
};

export default authMiddleware;
