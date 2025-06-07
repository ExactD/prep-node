import express, { Request, Response } from 'express';
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import testRoutes from './test';
import progressRoutes from './progress';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';

dotenv.config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const SALT_ROUNDS = 10; // Кількість раундів солювання для bcrypt
const VERIFICATION_CODE_LENGTH = 6;
const VERIFICATION_CODE_EXPIRES_MINUTES = 15;

// Підключення до PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: Number(process.env.DB_PORT),
  ssl: {
    rejectUnauthorized: false // Увага: це небезпечно для продакшена!
  }
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'nazarcukmihajlo9@gmail.com', // Ваш Gmail
    pass: process.env.EMAIL_PASSWORD || 'yyba psvo xwvx xrvk', // Пароль додатку
  },
  tls: {
    rejectUnauthorized: false, // Іноді потрібно для локального тестування
  },
});

interface VerificationData {
  code: string;
  expiresAt: number;
  email: string;
}

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use('/test', testRoutes);
app.use('/progress', progressRoutes);
import cors from 'cors';

const allowedOrigins = [
  'http://localhost:3000',
  'https://my-react-project-8o3p.vercel.app'
];

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    // Дозволити запити без origin (наприклад, Postman) або з дозволених сайтів
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization'],
};

app.use(cors(corsOptions));


if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
  console.warn('EMAIL_USER або EMAIL_PASSWORD не встановлені в .env файлі. В режимі розробки коди будуть показуватись у консолі.');
}

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

// Тимчасове сховище для кодів підтвердження (в продакшені використовуйте Redis або БД)
const emailVerificationCodes = new Map<string, VerificationData>();

app.post('/send-verification-code', async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email обов\'язковий' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Невірний формат email' });
  }

  try {
    const userResult = await pool.query(
      'SELECT verification_code, verification_code_expires_at FROM users WHERE email = $1',
      [email]
    );

    let verificationCode: string;
    let expiresAt: Date;

    if (userResult.rows.length > 0 &&
      userResult.rows[0].verification_code &&
      new Date(userResult.rows[0].verification_code_expires_at) > new Date()
    ) {
      verificationCode = userResult.rows[0].verification_code;
      expiresAt = userResult.rows[0].verification_code_expires_at;
    } else {
      verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      expiresAt = new Date(Date.now() + VERIFICATION_CODE_EXPIRES_MINUTES * 60 * 1000);

      if (userResult.rows.length > 0) {
        await pool.query(
          'UPDATE users SET verification_code = $1, verification_code_expires_at = $2 WHERE email = $3',
          [verificationCode, expiresAt, email]
        );
      } else {
        await pool.query(
          'INSERT INTO users (email, verification_code, verification_code_expires_at) VALUES ($1, $2, $3)',
          [email, verificationCode, expiresAt]
        );
      }
    }

    // Відправка email
    try {
      await transporter.sendMail({
          from: `"Тестування знань" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'Підтвердження email',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #2563eb;">Підтвердження email</h2>
              <p>Дякуємо за реєстрацію! Ваш код підтвердження:</p>
              <div style="background: #f3f4f6; padding: 16px; text-align: center; margin: 16px 0; font-size: 24px; font-weight: bold;">
                ${verificationCode}
              </div>

              <p>Посилання дійсне протягом ${VERIFICATION_CODE_EXPIRES_MINUTES} хвилин.</p>
              <p style="color: #6b7280; font-size: 14px;">Якщо ви не реєструвалися на нашому сайті, проігноруйте цей лист.</p>
            </div>
          `,
          text: `Ваш код підтвердження: ${verificationCode}\n`
        });

      return res.status(200).json({
        message: process.env.NODE_ENV === 'production'
          ? 'Код підтвердження відправлено на ваш email'
          : 'Код підтвердження доступний у консолі (dev mode)',
        devCode: process.env.NODE_ENV !== 'production' ? verificationCode : undefined,
      });

    } catch (error) {
      console.error('Помилка надсилання листа:', error);
      return res.status(500).json({ message: 'Помилка при надсиланні листа' });
    }

  } catch (error) {
    console.error('Помилка при генерації коду:', error);
    return res.status(500).json({ error: 'Помилка сервера' });
  }
});


// Перевірка коду
app.post('/verify-email-code', async (req: Request, res: Response) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ 
      error: 'Необхідні email та код підтвердження' 
    });
  }

  try {
    // Отримуємо користувача з бази даних
    const result = await pool.query(
      'SELECT id, verification_code, verification_code_expires_at FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Користувача з таким email не знайдено' 
      });
    }

    const user = result.rows[0];

    // Перевіряємо наявність коду
    if (!user.verification_code || !user.verification_code_expires_at) {
      return res.status(400).json({ 
        error: 'Код підтвердження не був відправлений на цей email' 
      });
    }

    // Перевіряємо термін дії коду
    if (new Date() > new Date(user.verification_code_expires_at)) {
      return res.status(400).json({ 
        error: 'Код протермінований. Запросіть новий код.' 
      });
    }

    // Перевіряємо відповідність коду
    if (user.verification_code !== code) {
      return res.status(400).json({ 
        error: 'Невірний код підтвердження',
        attemptsLeft: 'X' // Можна додати лічильник спроб
      });
    }

    // Позначаємо email як підтверджений
    await pool.query(
      'UPDATE users SET email_verified = true, verification_code = NULL, verification_code_expires_at = NULL WHERE email = $1',
      [email]
    );

    res.json({ 
      message: 'Email успішно підтверджено',
      verifiedEmail: email
    });
  } catch (error) {
    console.error('Помилка при перевірці коду:', error);
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

app.post('/resend-verification-code', async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email обов\'язковий' });
  }

  try {
    // Отримуємо поточний код з бази даних
    const userResult = await pool.query(
      'SELECT verification_code, verification_code_expires_at FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Користувача з таким email не знайдено' });
    }

    const user = userResult.rows[0];
    let verificationCode = user.verification_code;
    let expiresAt = user.verification_code_expires_at;

    // Якщо код протермінований або відсутній - генеруємо новий
    if (!verificationCode || !expiresAt || new Date() > new Date(expiresAt)) {
      verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      expiresAt = new Date(Date.now() + VERIFICATION_CODE_EXPIRES_MINUTES * 60 * 1000);

      // Оновлюємо код у базі даних
      await pool.query(
        'UPDATE users SET verification_code = $1, verification_code_expires_at = $2 WHERE email = $3',
        [verificationCode, expiresAt, email]
      );
    }

    // Відправка email (як у оригінальному методі)
    if (process.env.NODE_ENV === 'production' && process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
      await transporter.sendMail({
        from: `"Тестування знань" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Код підтвердження email',
        text: `Ваш код підтвердження: ${verificationCode}`,
        html: `<p>Ваш код підтвердження: <strong>${verificationCode}</strong></p>
               <p>Код дійсний протягом ${VERIFICATION_CODE_EXPIRES_MINUTES} хвилин.</p>`,
      });
    } else {
      console.log(`[DEV] Код підтвердження для ${email}: ${verificationCode}`);
      console.log(`[DEV] Код дійсний до: ${expiresAt}`);
    }

    res.json({
      message: process.env.NODE_ENV === 'production' 
        ? 'Код підтвердження відправлено на ваш email' 
        : 'Код підтвердження доступний у консолі (dev mode)',
      devCode: process.env.NODE_ENV !== 'production' ? verificationCode : undefined,
    });
  } catch (error) {
    console.error('Помилка при повторному надсиланні коду:', error);
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

// Додати цей ендпоінт перед іншими маршрутами
app.post('/check-email', async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email обов\'язковий' });
  }

  try {
    const result = await pool.query(
      'SELECT id, email_verified FROM users WHERE email = $1 AND password IS NOT NULL',
      [email]
    );

    if (result.rows.length > 0) {
      return res.json({
        exists: true,
        verified: result.rows[0].email_verified
      });
    }

    res.json({ exists: false });
  } catch (error) {
    console.error('Помилка при перевірці email:', error);
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

// Перевірка коду для скидання пароля
app.post('/verify-password-reset-code', async (req: Request, res: Response) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ 
      error: 'Необхідні email та код підтвердження' 
    });
  }

  try {
    // Отримуємо користувача з бази даних
    const result = await pool.query(
      'SELECT id, reset_password_code, reset_password_expires FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Користувача з таким email не знайдено' 
      });
    }

    const user = result.rows[0];

    // Перевіряємо наявність коду
    if (!user.reset_password_code || !user.reset_password_expires) {
      return res.status(400).json({ 
        error: 'Код скидання пароля не був відправлений на цей email' 
      });
    }

    // Перевіряємо термін дії коду
    if (new Date() > new Date(user.reset_password_expires)) {
      return res.status(400).json({ 
        error: 'Код протермінований. Запросіть новий код.' 
      });
    }

    // Перевіряємо відповідність коду
    if (user.reset_password_code !== code) {
      return res.status(400).json({ 
        error: 'Невірний код скидання пароля',
        attemptsLeft: 'X' // Можна додати лічильник спроб
      });
    }

    res.json({ 
      message: 'Код скидання пароля підтверджено',
      verifiedEmail: email
    });
  } catch (error) {
    console.error('Помилка при перевірці коду скидання пароля:', error);
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

// Запит на скидання пароля (оновлена версія)
app.post('/request-password-reset', async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email обов\'язковий' });
  }

  try {
    // Перевіряємо, чи існує користувач з таким email
    const userResult = await pool.query(
      'SELECT id, email_verified FROM users WHERE email = $1 AND password IS NOT NULL',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Користувача з таким email не знайдено' });
    }

    const user = userResult.rows[0];
    if (!user.email_verified) {
      return res.status(400).json({ error: 'Email не підтверджений. Спочатку підтвердіть email.' });
    }

    // Генеруємо код скидання
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + VERIFICATION_CODE_EXPIRES_MINUTES * 60 * 1000);

    // Зберігаємо код в базу даних
    await pool.query(
      `UPDATE users 
      SET reset_password_code = $1, 
          reset_password_expires = $2 
      WHERE email = $3`,
      [resetCode, expiresAt, email]
    );

    try {
      await transporter.sendMail({
          from: `"Тестування знань" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'Підтвердження скидання паролю',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #2563eb;">Підтвердження коду скидання пароля</h2>
              <p>Ваш код підтвердження:</p>
              <div style="background: #f3f4f6; padding: 16px; text-align: center; margin: 16px 0; font-size: 24px; font-weight: bold;">
                ${resetCode}
              </div>

              <p>Посилання дійсне протягом ${VERIFICATION_CODE_EXPIRES_MINUTES} хвилин.</p>
              <p style="color: #6b7280; font-size: 14px;">Якщо ви не реєструвалися на нашому сайті, проігноруйте цей лист.</p>
            </div>
          `,
          text: `Ваш код підтвердження: ${resetCode}\n`
        });

      return res.status(200).json({
        message: process.env.NODE_ENV === 'production'
          ? 'Код підтвердження відправлено на ваш email'
          : 'Код підтвердження доступний у консолі (dev mode)',
        devCode: process.env.NODE_ENV !== 'production' ? resetCode : undefined,
      });

    } catch (error) {
      console.error('Помилка надсилання листа:', error);
      return res.status(500).json({ message: 'Помилка при надсиланні листа' });
    }

  } catch (error) {
    console.error('Помилка при запиті скидання пароля:', error);
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

// Повторне надсилання коду для скидання пароля
app.post('/resend-password-reset-code', async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email обов\'язковий' });
  }

  try {
    // Отримуємо поточний код з бази даних
    const userResult = await pool.query(
      'SELECT reset_password_code, reset_password_expires FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Користувача з таким email не знайдено' });
    }

    const user = userResult.rows[0];
    let resetCode = user.reset_password_code;
    let expiresAt = user.reset_password_expires;

    // Якщо код протермінований або відсутній - генеруємо новий
    if (!resetCode || !expiresAt || new Date() > new Date(expiresAt)) {
      resetCode = Math.floor(100000 + Math.random() * 900000).toString();
      expiresAt = new Date(Date.now() + VERIFICATION_CODE_EXPIRES_MINUTES * 60 * 1000);

      // Оновлюємо код у базі даних
      await pool.query(
        'UPDATE users SET reset_password_code = $1, reset_password_expires = $2 WHERE email = $3',
        [resetCode, expiresAt, email]
      );
    }

    // Відправка email
    try {
      await transporter.sendMail({
          from: `"Тестування знань" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'Підтвердження скидання паролю',
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h2 style="color: #2563eb;">Підтвердження коду скидання пароля</h2>
              <p>Ваш код підтвердження:</p>
              <div style="background: #f3f4f6; padding: 16px; text-align: center; margin: 16px 0; font-size: 24px; font-weight: bold;">
                ${resetCode}
              </div>

              <p>Посилання дійсне протягом ${VERIFICATION_CODE_EXPIRES_MINUTES} хвилин.</p>
              <p style="color: #6b7280; font-size: 14px;">Якщо ви не реєструвалися на нашому сайті, проігноруйте цей лист.</p>
            </div>
          `,
          text: `Ваш код підтвердження: ${resetCode}\n`
        });

      return res.status(200).json({
        message: process.env.NODE_ENV === 'production'
          ? 'Код підтвердження відправлено на ваш email'
          : 'Код підтвердження доступний у консолі (dev mode)',
        devCode: process.env.NODE_ENV !== 'production' ? resetCode : undefined,
      });

    } catch (error) {
      console.error('Помилка надсилання листа:', error);
      return res.status(500).json({ message: 'Помилка при надсиланні листа' });
    }

  } catch (error) {
    console.error('Помилка при повторному надсиланні коду скидання пароля:', error);
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

// Скидання пароля після підтвердження коду
app.post('/reset-password', async (req: Request, res: Response) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({ error: 'Необхідні email та новий пароль' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Пароль повинен містити щонайменше 6 символів' });
  }

  try {
    // Перевіряємо, чи був підтверджений код скидання
    const userResult = await pool.query(
      `SELECT id FROM users 
      WHERE email = $1 
      AND reset_password_code IS NULL 
      AND reset_password_expires IS NULL`,
      [email]
    );

    // Хешуємо новий пароль
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Оновлюємо пароль
    await pool.query(
      'UPDATE users SET password = $1 WHERE email = $2',
      [hashedPassword, email]
    );

    res.json({ message: 'Пароль успішно змінено' });

  } catch (error) {
    console.error('Помилка при скиданні пароля:', error);
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

// Реєстрація користувача з хешуванням пароля
app.post('/register', async (req: Request, res: Response) => {
  const { name, email, password, code } = req.body;

  if (!name || !email || !password || !code) {
    return res.status(400).json({ error: 'Усі поля обов\'язкові' });
  }

  try {
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1 AND password IS NOT NULL',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Користувач вже зареєстрований' });
    }

    // Решта логіки реєстрації залишається без змін
    const userResult = await pool.query(
      'SELECT id, verification_code, verification_code_expires_at FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'Спочатку отримайте код підтвердження' });
    }

    const user = userResult.rows[0];

    if (!user.verification_code || !user.verification_code_expires_at) {
      return res.status(400).json({ error: 'Код підтвердження не був відправлений' });
    }

    if (new Date() > new Date(user.verification_code_expires_at)) {
      return res.status(400).json({ error: 'Код протермінований' });
    }

    if (user.verification_code !== code) {
      return res.status(400).json({ error: 'Невірний код підтвердження' });
    }

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Користувач вже зареєстрований' });
    }

    // Хешування пароля
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Оновлюємо користувача
    const updatedUser = await pool.query(
      `UPDATE users 
       SET name = $1, password = $2, email_verified = true, 
           verification_code = NULL, verification_code_expires_at = NULL, created_at = NOW()
       WHERE email = $3 
       RETURNING id, name, email, created_at`,
      [name, hashedPassword, email]
    );

    res.status(201).json({
      message: 'Користувач успішно зареєстрований',
      user: updatedUser.rows[0]
    });
  } catch (error) {
    console.error('Помилка при реєстрації:', error);
    res.status(500).json({ error: 'Помилка сервера при реєстрації' });
  }
});

// Покращений логін користувача
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
      'SELECT id, name, email, password, email_verified FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        error: 'Невірний email або пароль' 
      });
    }

    const user = result.rows[0];

    // Перевірка чи email підтверджений
    if (!user.email_verified) {
      return res.status(403).json({
        error: 'Email не підтверджено. Будь ласка, підтвердіть свій email.'
      });
    }

    // Порівняння пароля з хешем
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ 
        error: 'Невірний email або пароль' 
      });
    }

    // Генерація JWT токена
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email,
        name: user.name
      },
      JWT_SECRET,
      { expiresIn: '168h' }
    );

    // Встановлення cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000 * 7,
      sameSite: 'none',
      domain: ''
      //domain: '.vercel.app'
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
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    });
    
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

// Отримати всіх користувачів
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