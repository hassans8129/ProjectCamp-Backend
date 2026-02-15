import dotenv from 'dotenv';
import app from './app.js';
import connectDB from './db/index.js';

dotenv.config({
  path: './.env',
});

const port = process.env.PORT || 3000;
console.log('MONGO_URI: ', process.env.MONGO_URI);

connectDB()
  .then(() => {
    app.listen(port, () => {
      console.log(`Running on port ${port}`);
    });
  })
  .catch((err) => {
    console.error('mongoDb connection error', err);
    process.exit(1);
  });
