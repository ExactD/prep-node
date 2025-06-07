import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Підключення до PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: Number(process.env.DB_PORT),
});

// Middleware
app.use(express.json());
app.use(cookieParser());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization'); // Додали Authorization
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Middleware для перевірки JWT
const authenticateToken = (req: any, res: Response, next: any) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: 'Токен доступу відсутній' });
  }

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) {
      return res.status(403).json({ error: 'Недійсний токен' });
    }
    req.user = user;
    next();
  });
};

// Додати новий запис про прогрес користувача в тесті
app.post('/add', authenticateToken, async (req: any, res: Response) => {
  try {
    // Отримання та приведення значень
    const userId = Number(req.body.user_id);
    const testId = Number(req.body.test_id);
    const task = Number(req.body.task);
    const value = Number(req.body.value);

    // Перевірка, що всі поля — числа (double)
    if (
      [userId, testId, task, value].some(v => isNaN(v))
    ) {
      return res.status(400).json({
        error: 'user_id, test_id, task і value мають бути числовими значеннями (типу double).'
      });
    }

    // Запит до бази даних
    const result = await pool.query(
      'INSERT INTO user_test_progress (user_id, test_id, task, value) VALUES ($1, $2, $3, $4) RETURNING *',
      [userId, testId, task, value]
    );

    res.status(201).json({
      message: 'Запис про прогрес успішно додано',
      progress: result.rows[0]
    });
  } catch (err) {
    console.error('Помилка при додаванні запису про прогрес:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

// Оновити (замінити) значення для конкретного користувача, тесту та завдання
app.put('/update', authenticateToken, async (req: any, res: Response) => {
  const { user_id, test_id, task, value } = req.body;

  try {
    // Спочатку перевіримо, чи існує запис
    const checkResult = await pool.query(
      'SELECT id FROM user_test_progress WHERE user_id = $1 AND test_id = $2 AND task = $3',
      [user_id, test_id, task]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Запис не знайдено',
        details: 'Для оновлення запису він повинен існувати. Використайте POST для створення нового запису.'
      });
    }

    // Якщо запис існує - оновлюємо
    const updateResult = await pool.query(
      'UPDATE user_test_progress SET value = $1 WHERE user_id = $2 AND test_id = $3 AND task = $4 RETURNING *',
      [value, user_id, test_id, task]
    );

    res.json({
      message: 'Значення успішно оновлено',
      updated_record: updateResult.rows[0]
    });
  } catch (err) {
    console.error('Помилка при оновленні значення:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

// Видалити всі записи про прогрес користувача для конкретного тесту
app.delete('/delete', authenticateToken, async (req: any, res: Response) => {
  const { user_id } = req.body;

  try {
    const result = await pool.query(
      'DELETE FROM user_test_progress WHERE user_id = $1 RETURNING *',
      [user_id]
    );

    res.json({
      message: 'Записи про прогрес успішно видалено',
      deleted_count: result.rowCount
    });
  } catch (err) {
    console.error('Помилка при видаленні записів про прогрес:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

app.post('/remove', authenticateToken, async (req: any, res: Response) => {
  const { user_id, test_id, task } = req.body;

  try {
    const result = await pool.query(
      'DELETE FROM user_test_progress WHERE user_id = $1 AND test_id = $2 AND task = $3 RETURNING *',
      [user_id, test_id, task]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        error: 'Запис не знайдено для видалення',
        details: `Для user_id: ${user_id}, test_id: ${test_id}, task: ${task}`
      });
    }

    res.json({
      message: 'Запис про прогрес успішно видалено',
      deleted: result.rows[0]
    });
  } catch (err) {
    console.error('Помилка при видаленні запису про прогрес:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

// Отримати всю інформацію про конкретний запис за user_id та task_id
app.post('/get', authenticateToken, async (req: any, res: Response) => {
  const { user_id } = req.body;

  try {
    const result = await pool.query(
      'SELECT user_id, test_id, task, value FROM user_test_progress WHERE user_id = $1',
      [user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Записи не знайдено',
        details: `Для user_id: ${user_id}`
      });
    }

    res.json({
      message: 'Записи знайдено',
      records: result.rows,
      count: result.rows.length
    });
  } catch (err) {
    console.error('Помилка при отриманні записів:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

export default app;