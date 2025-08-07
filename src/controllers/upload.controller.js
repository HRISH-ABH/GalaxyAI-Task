import cloudinary from "../service/cloudinary.service.js";
import { PassThrough } from 'stream';



 const uploadFileController = async (req, res) => {
   try {
    const uploadedUrls = [];

    for (const file of req.files) {
      const streamUpload = () =>
        new Promise((resolve, reject) => {
          const bufferStream = new PassThrough();

          bufferStream.end(file.buffer);

          const stream = cloudinary.uploader.upload_stream(
            { resource_type: 'image' },
            (error, result) => {
              if (error) reject(error);
              else resolve(result.secure_url);
            }
          );

          bufferStream.pipe(stream);
        });

      const url = await streamUpload();
      uploadedUrls.push(url);
    }

    res.json({ urls: uploadedUrls });
  } catch (error) {
    res.status(500).json({ error: 'Upload failed', details: error.message });
  }
};

export{
    uploadFileController
}




