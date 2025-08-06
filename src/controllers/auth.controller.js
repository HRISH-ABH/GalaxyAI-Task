import userModel from "../models/user.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const generateToken = (userId) =>
  jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "7d" });

const registerController = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const existingUser = await userModel.findOne({ email });
    if (user) {
      return res.status(400).json({
        message: "User already exists! Try Loggin In",
      });
    }
    const hashPassword = await bcrypt.hash(password, 10);
    const user = await userModel.create({
      name,
      email,
      hashPassword,
    });
    const token = generateToken(user._id);
    res.status(201).json({
      token,
      user,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};

const loginController = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await userModel.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        message: "Invalid credentials!",
      });
    }

    const token = generateToken(user._id);
    res.status(200).json({
      token,
      user,
    });
  } catch (error) {
    res.status(500).json({
      message: error.message,
    });
  }
};

export {
    registerController,
    loginController
}