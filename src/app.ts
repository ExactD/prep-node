import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import testRoutes from './test';
import progressRoutes from './progress';
import bcrypt from 'bcrypt';


dotenv.config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const SALT_ROUNDS = 10; // Кількість раундів солювання для bcrypt

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
app.use('/test', testRoutes);
app.use('/progress', progressRoutes);

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
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

    // Хешування паролю
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Створення нового користувача
    const result = await pool.query(
      'INSERT INTO users (name, email, password, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, name, email, created_at',
      [name, email, hashedPassword]
    );

    const user = result.rows[0];

    // Створення JWT токену
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Встановлення cookie з токеном
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 години
    });

    res.status(201).json({
      message: 'Користувач успішно зареєстрований',
      user: { id: user.id, name: user.name, email: user.email, created_at: user.created_at }
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
    // Отримання користувача з бази даних
    const result = await pool.query(
      'SELECT id, name, email, password FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        error: 'Невірний email або пароль' 
      });
    }

    const user = result.rows[0];

    // Порівняння хешованого паролю з введеним
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ 
        error: 'Невірний email або пароль' 
      });
    }

    // Створення JWT токену
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Встановлення cookie з токеном
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 години
    });

    // Видаляємо пароль з відповіді
    const { password: _, ...userWithoutPassword } = user;

    res.json({
      message: 'Успішний вхід',
      user: userWithoutPassword
    });
  } catch (err) {
    console.error('Помилка при логіні:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

// Вихід користувача
app.get('/logout', (req: Request, res: Response) => {
  try {
    // Очищаємо cookie з токеном, встановлюючи ті самі параметри, що і при створенні
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict', // Додатковий захист від CSRF
      path: '/', // Вказуємо той самий шлях, що і для встановлення cookie
    });

    // Додатково можна додати логіку для інвалідації токену, якщо використовується blacklist
    // Наприклад, якщо ви хочете зробити токен недійсним до закінчення його терміну
    
    res.status(200).json({ 
      success: true,
      message: 'Успішний вихід із системи' 
    });
  } catch (err) {
    console.error('Помилка при виході:', err);
    res.status(500).json({ 
      success: false,
      error: 'Не вдалося виконати вихід' 
    });
  }
});

// Отримати профіль поточного користувача
app.get('/profile', authenticateToken, async (req: any, res: Response) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, created_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Користувача не знайдено' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Помилка при отриманні профілю:', err);
    res.status(500).json({ error: 'Внутрішня помилка сервера' });
  }
});

// Отримати всіх користувачів (потребує авторизації)
app.get('/users', authenticateToken, async (_req: Request, res: Response) => {
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

// Оновити профіль поточного користувача
app.put('/profile', authenticateToken, async (req: any, res: Response) => {
  const { name } = req.body;

  try {
    const result = await pool.query(
      'UPDATE users SET name = COALESCE($1, name) WHERE id = $2 RETURNING id, name, email, created_at',
      [name, req.user.id]
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

export default app;