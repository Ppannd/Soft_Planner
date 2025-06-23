// api/auth.js
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';

// Инициализация базы данных
let db;
async function initDB() {
  db = await open({
    filename: './auth.db',
    driver: sqlite3.Database
  });

  // Создаем таблицу пользователей, если ее нет
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

initDB();

// Регистрация нового пользователя
export async function POST(request) {
  const { name, email, password } = await request.json();

  // Простая валидация
  if (!name || !email || !password) {
    return new Response(JSON.stringify({ error: 'Все поля обязательны' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    // Проверяем, есть ли уже пользователь с таким email
    const existingUser = await db.get('SELECT * FROM users WHERE email = ?', email);
    if (existingUser) {
      return new Response(JSON.stringify({ error: 'Пользователь уже существует' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Хешируем пароль
    const hashedPassword = await bcrypt.hash(password, 10);

    // Сохраняем пользователя в базу
    const result = await db.run(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      name, email, hashedPassword
    );

    return new Response(JSON.stringify({ 
      success: true,
      user: { id: result.lastID, name, email }
    }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Registration error:', error);
    return new Response(JSON.stringify({ error: 'Ошибка сервера' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Авторизация пользователя
export async function GET(request) {
  const url = new URL(request.url);
  const email = url.searchParams.get('email');
  const password = url.searchParams.get('password');

  if (!email || !password) {
    return new Response(JSON.stringify({ error: 'Email и пароль обязательны' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    // Ищем пользователя в базе
    const user = await db.get('SELECT * FROM users WHERE email = ?', email);
    if (!user) {
      return new Response(JSON.stringify({ error: 'Неверные учетные данные' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Проверяем пароль
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return new Response(JSON.stringify({ error: 'Неверные учетные данные' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Возвращаем данные пользователя (без пароля)
    const { password: _, ...userData } = user;
    return new Response(JSON.stringify({ 
      success: true,
      user: userData
    }), {
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Login error:', error);
    return new Response(JSON.stringify({ error: 'Ошибка сервера' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
