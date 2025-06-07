// server.ts або index.ts
import app from './app';
import dotenv from 'dotenv';

dotenv.config();

const PORT = process.env.PORT || 5414;

app.listen(PORT, () => {
  console.log(`🚀 Сервер працює на http://localhost:${PORT}`);
});