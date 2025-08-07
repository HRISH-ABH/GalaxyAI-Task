import multer from "multer";

const storage = multer.memoryStorage(); 
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, 
});

export const uploadMiddleware = upload.array("files",5);
