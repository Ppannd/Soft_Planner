// Файл: api/auth.js (для Vercel Serverless Functions)
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';

// Открываем/создаем базу данных
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

// Инициализация БД при старте
initDB();

export async function POST(request) {
  const { name, email, password } = await request.json();

  // Валидация
  if (!name || !email || !password) {
    return new Response(JSON.stringify({ error: 'Все поля обязательны' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (password.length < 8) {
    return new Response(JSON.stringify({ error: 'Пароль должен быть не менее 8 символов' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    // Проверяем, есть ли уже пользователь с таким email
    const existingUser = await db.get('SELECT * FROM users WHERE email = ?', email);
    if (existingUser) {
      return new Response(JSON.stringify({ error: 'Пользователь с таким email уже существует' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Хешируем пароль
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    // Сохраняем пользователя в БД
    await db.run(
      'INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)',
      userId, name, email, hashedPassword
    );

    return new Response(JSON.stringify({ success: true, userId }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: 'Ошибка сервера' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

export async function GET(request) {
  const { email, password } = Object.fromEntries(request.url.searchParams.entries());

  if (!email || !password) {
    return new Response(JSON.stringify({ error: 'Email и пароль обязательны' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    // Ищем пользователя в БД
    const user = await db.get('SELECT * FROM users WHERE email = ?', email);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Неверный email или пароль' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Проверяем пароль
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return new Response(JSON.stringify({ error: 'Неверный email или пароль' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Возвращаем успешный ответ (без пароля)
    const { password: _, ...userData } = user;
    return new Response(JSON.stringify({ success: true, user: userData }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    };

  } catch (error) {
    return new Response(JSON.stringify({ error: 'Ошибка сервера' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
