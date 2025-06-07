import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import dotenv from 'dotenv';

// Ініціалізація
dotenv.config();
const app = express();
const PORT = process.env.PORT || 5005;

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

// Маршрути
app.get('/', (req: Request, res: Response) => {
  res.send('Привіт! Сервер працює 🚀');
});

// Реєстрація користувача
app.post('/register', async (req: Request, res: Response) => {
  const { name, email, password } = req.body;

  // Перевірка обов'язкових полів
  if (!name || !email || !password) {
    return res.status(400).json({ 
      error: 'Імʼя, email та пароль є обовʼязковими полями' 
    });
  }

  try {
    // Перевірка чи існує користувач з таким email
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ 
        error: 'Користувач з таким email вже існує' 
      });
    }

    // Створення нового користувача
    const result = await pool.query(
      'INSERT INTO users (name, email, password, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, name, email, created_at',
      [name, email, password]
    );

    res.status(201).json({
      message: 'Користувач успішно зареєстрований',
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Помилка при реєстрації користувача:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

// Логін користувача
app.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ 
      error: 'Email та пароль є обовʼязковими' 
    });
  }

  try {
    const result = await pool.query(
      'SELECT id, name, email FROM users WHERE email = $1 AND password = $2',
      [email, password]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        error: 'Невірний email або пароль' 
      });
    }

    res.json({
      message: 'Успішний вхід',
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Помилка при логіні:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

// Отримати профіль користувача за ID
app.get('/users/:id', async (req: Request, res: Response) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      'SELECT id, name, email, created_at FROM users WHERE id = $1',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Користувача не знайдено' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Помилка при отриманні користувача:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

// Отримати всіх користувачів (без паролів)
app.get('/users', async (_req: Request, res: Response) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Помилка при зчитуванні користувачів:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

// Оновити профіль користувача
app.put('/users/:id', async (req: Request, res: Response) => {
  const { id } = req.params;
  const { name } = req.body;

  try {
    const result = await pool.query(
      'UPDATE users SET name = COALESCE($1, name) WHERE id = $2 RETURNING id, name, email, created_at',
      [name, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Користувача не знайдено' });
    }

    res.json({
      message: 'Профіль оновлено',
      user: result.rows[0]
    });
  } catch (err) {
    console.error('Помилка при оновленні користувача:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`🚀 Сервер працює на http://localhost:${PORT}`);
});