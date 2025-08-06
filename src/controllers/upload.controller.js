import {uploader} from "../service/cloudinary.service.js"
import multer, { memoryStorage } from 'multer';
const storage = memoryStorage();
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

export const uploadMiddleware = upload.single('file');

export async function uploadFileController(req, res) {
  if (!req.file) return res.status(400).json({ message: 'No file provided' });

  const result = await new Promise((resolve, reject) => {
    uploader.upload_stream(
      { resource_type: 'auto', folder: 'chat-attachments' },
      (error, result) => {
        if (error) reject(error);
        else resolve(result);
      }
    ).end(req.file.buffer);
  });

  res.json({
    url: result.secure_url,
    filename: req.file.originalname,
    type: req.file.mimetype.startsWith('image/') ? 'image' : 'file',
  });
}
export{
    uploadFileController
}