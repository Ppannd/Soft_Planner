import { json } from '@vercel/remix';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

// Инициализация БД
let db;
async function initDB() {
  db = await open({
    filename: './auth.db',
    driver: sqlite3.Database
  });
  
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

initDB();

export async function POST({ request }) {
  const { name, email, password } = await request.json();

  // Валидация
  if (!name || !email || !password) {
    return json({ error: 'Все поля обязательны' }, { status: 400 });
  }

  try {
    // Проверка существующего пользователя
    const existingUser = await db.get('SELECT * FROM users WHERE email = ?', email);
    if (existingUser) {
      return json({ error: 'Пользователь с таким email уже существует' }, { status: 400 });
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    // Сохранение пользователя
    await db.run(
      'INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)',
      userId, name, email, hashedPassword
    );

    return json({ 
      success: true, 
      user: { id: userId, name, email } 
    }, { status: 201 });

  } catch (error) {
    console.error('Registration error:', error);
    return json({ error: 'Ошибка сервера' }, { status: 500 });
  }
}

export async function GET({ request }) {
  const url = new URL(request.url);
  const email = url.searchParams.get('email');
  const password = url.searchParams.get('password');

  if (!email || !password) {
    return json({ error: 'Email и пароль обязательны' }, { status: 400 });
  }

  try {
    // Поиск пользователя
    const user = await db.get('SELECT * FROM users WHERE email = ?', email);
    if (!user) {
      return json({ error: 'Неверный email или пароль' }, { status: 401 });
    }

    // Проверка пароля
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return json({ error: 'Неверный email или пароль' }, { status: 401 });
    }

    // Успешный ответ
    const { password: _, ...userData } = user;
    return json({ 
      success: true, 
      user: userData 
    });

  } catch (error) {
    console.error('Login error:', error);
    return json({ error: 'Ошибка сервера' }, { status: 500 });
  }
}
