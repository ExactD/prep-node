import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

export const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: String(process.env.DB_PASSWORD), // Явне перетворення на рядок
  port: Number(process.env.DB_PORT),
});

pool.connect()
  .then(() => console.log('✅ Підключено до PostgreSQL'))
  .catch((err) => console.error('❌ Помилка підключення:', err));