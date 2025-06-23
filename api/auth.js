// Файл: api/auth.js
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';

// Инициализация базы данных
let db;
async function initDB() {
  db = await open({
    filename: './database.db',
    driver: sqlite3.Database
  });

  // Создаем таблицы, если их нет
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      userId TEXT,
      name TEXT,
      description TEXT,
      priority TEXT,
      date TEXT,
      time TEXT,
      tags TEXT,
      completed INTEGER DEFAULT 0,
      workspace TEXT DEFAULT 'default',
      FOREIGN KEY(userId) REFERENCES users(id)
    );
    
    CREATE TABLE IF NOT EXISTS workspaces (
      id TEXT PRIMARY KEY,
      userId TEXT,
      name TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(userId) REFERENCES users(id)
    );
  `);
}

initDB();

// Вспомогательные функции
function formatDate(date) {
  return date.toISOString().split('T')[0];
}

// API для аутентификации
export async function POST(request) {
  const { name, email, password } = await request.json();

  if (!name || !email || !password) {
    return new Response(JSON.stringify({ error: 'Все поля обязательны' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  try {
    // Проверяем, есть ли уже пользователь
    const existingUser = await db.get('SELECT * FROM users WHERE email = ?', email);
    if (existingUser) {
      return new Response(JSON.stringify({ error: 'Пользователь уже существует' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Хешируем пароль
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    // Сохраняем пользователя
    await db.run(
      'INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)',
      userId, name, email, hashedPassword
    );

    // Создаем дефолтный workspace
    await db.run(
      'INSERT INTO workspaces (id, userId, name) VALUES (?, ?, ?)',
      uuidv4(), userId, 'My Workspace'
    );

    return new Response(JSON.stringify({ 
      success: true, 
      userId,
      name,
      email
    }), {
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
    // Ищем пользователя
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
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: 'Ошибка сервера' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// API для задач
export async function PUT(request) {
  const { action, ...data } = await request.json();

  try {
    switch (action) {
      case 'get-tasks':
        const tasks = await db.all(
          'SELECT * FROM tasks WHERE userId = ? AND date = ? AND workspace = ?',
          data.userId, data.date, data.workspace || 'default'
        );
        return new Response(JSON.stringify({ success: true, tasks }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });

      case 'add-task':
        const taskId = uuidv4();
        await db.run(
          `INSERT INTO tasks (id, userId, name, description, priority, date, time, tags, workspace)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          taskId, data.userId, data.name, data.description, data.priority, 
          data.date, data.time, JSON.stringify(data.tags || []), data.workspace || 'default'
        );
        return new Response(JSON.stringify({ success: true, taskId }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' }
        });

      case 'update-task':
        await db.run(
          `UPDATE tasks SET 
            name = ?, description = ?, priority = ?, date = ?, time = ?, tags = ?, completed = ?
           WHERE id = ? AND userId = ?`,
          data.name, data.description, data.priority, data.date, data.time, 
          JSON.stringify(data.tags || []), data.completed ? 1 : 0, 
          data.taskId, data.userId
        );
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });

      case 'delete-task':
        await db.run('DELETE FROM tasks WHERE id = ? AND userId = ?', data.taskId, data.userId);
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });

      default:
        return new Response(JSON.stringify({ error: 'Неизвестное действие' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
    }
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Ошибка сервера' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// API для workspace
export async function PATCH(request) {
  const { action, ...data } = await request.json();

  try {
    switch (action) {
      case 'get-workspaces':
        const workspaces = await db.all(
          'SELECT * FROM workspaces WHERE userId = ?',
          data.userId
        );
        return new Response(JSON.stringify({ success: true, workspaces }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });

      case 'create-workspace':
        const workspaceId = uuidv4();
        await db.run(
          'INSERT INTO workspaces (id, userId, name) VALUES (?, ?, ?)',
          workspaceId, data.userId, data.name
        );
        return new Response(JSON.stringify({ success: true, workspaceId }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' }
        });

      default:
        return new Response(JSON.stringify({ error: 'Неизвестное действие' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
    }
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Ошибка сервера' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
