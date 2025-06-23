// api/auth.js
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';

// Инициализация базы данных
let db;
async function initDB() {
  db = await open({
    filename: './database.db',
    driver: sqlite3.Database
  });

  // Создаем таблицы
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      language TEXT DEFAULT 'en',
      theme TEXT DEFAULT 'dark',
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS workspaces (
      id TEXT PRIMARY KEY,
      name TEXT,
      ownerId TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(ownerId) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS workspace_members (
      workspaceId TEXT,
      userId TEXT,
      role TEXT DEFAULT 'member',
      PRIMARY KEY (workspaceId, userId),
      FOREIGN KEY(workspaceId) REFERENCES workspaces(id),
      FOREIGN KEY(userId) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      title TEXT,
      description TEXT,
      priority TEXT,
      dueDate TEXT,
      completed INTEGER DEFAULT 0,
      workspaceId TEXT,
      creatorId TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(workspaceId) REFERENCES workspaces(id),
      FOREIGN KEY(creatorId) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS invitations (
      id TEXT PRIMARY KEY,
      workspaceId TEXT,
      fromUserId TEXT,
      toUserId TEXT,
      status TEXT DEFAULT 'pending',
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(workspaceId) REFERENCES workspaces(id),
      FOREIGN KEY(fromUserId) REFERENCES users(id),
      FOREIGN KEY(toUserId) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      userId TEXT,
      type TEXT,
      content TEXT,
      isRead INTEGER DEFAULT 0,
      relatedId TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(userId) REFERENCES users(id)
    );
  `);
}

initDB();

// Вспомогательные функции
function handleError(error, message = 'Server error') {
  console.error(error);
  return {
    status: 500,
    body: { error: message }
  };
}

// Основные обработчики API
export default {
  // Регистрация
  async register({ name, email, password }) {
    try {
      const existingUser = await db.get('SELECT * FROM users WHERE email = ?', email);
      if (existingUser) {
        return { status: 400, body: { error: 'User already exists' } };
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const userId = uuidv4();

      await db.run(
        'INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)',
        userId, name, email, hashedPassword
      );

      // Создаем персональное рабочее пространство
      const workspaceId = uuidv4();
      await db.run(
        'INSERT INTO workspaces (id, name, ownerId) VALUES (?, ?, ?)',
        workspaceId, `${name}'s Workspace`, userId
      );

      return { 
        status: 201, 
        body: { 
          success: true,
          user: { id: userId, name, email }
        }
      };
    } catch (error) {
      return handleError(error, 'Registration failed');
    }
  },

  // Авторизация
  async login({ email, password }) {
    try {
      const user = await db.get('SELECT * FROM users WHERE email = ?', email);
      if (!user) {
        return { status: 401, body: { error: 'Invalid credentials' } };
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return { status: 401, body: { error: 'Invalid credentials' } };
      }

      const { password: _, ...userData } = user;
      return {
        status: 200,
        body: { success: true, user: userData }
      };
    } catch (error) {
      return handleError(error, 'Login failed');
    }
  },

  // Рабочие пространства
  async getWorkspaces(userId) {
    try {
      const workspaces = await db.all(`
        SELECT w.* FROM workspaces w
        JOIN workspace_members m ON w.id = m.workspaceId
        WHERE m.userId = ?
      `, userId);

      return { status: 200, body: { workspaces } };
    } catch (error) {
      return handleError(error, 'Failed to get workspaces');
    }
  },

  // Приглашения
  async sendInvitation({ fromUserId, toUserId, workspaceId }) {
    try {
      // Проверяем существование пользователя
      const userExists = await db.get('SELECT id FROM users WHERE id = ?', toUserId);
      if (!userExists) {
        return { status: 404, body: { error: 'User not found' } };
      }

      // Проверяем права доступа
      const isOwner = await db.get(`
        SELECT id FROM workspaces 
        WHERE id = ? AND ownerId = ?
      `, workspaceId, fromUserId);

      if (!isOwner) {
        return { status: 403, body: { error: 'No permission' } };
      }

      // Создаем приглашение
      const invitationId = uuidv4();
      await db.run(`
        INSERT INTO invitations (id, workspaceId, fromUserId, toUserId)
        VALUES (?, ?, ?, ?)
      `, invitationId, workspaceId, fromUserId, toUserId);

      // Создаем уведомление
      const notificationId = uuidv4();
      const fromUser = await db.get('SELECT name FROM users WHERE id = ?', fromUserId);
      const workspace = await db.get('SELECT name FROM workspaces WHERE id = ?', workspaceId);

      await db.run(`
        INSERT INTO notifications (id, userId, type, content, relatedId)
        VALUES (?, ?, ?, ?, ?)
      `, notificationId, toUserId, 'invitation', 
         `${fromUser.name} invited you to ${workspace.name}`, 
         invitationId);

      return { status: 201, body: { success: true } };
    } catch (error) {
      return handleError(error, 'Failed to send invitation');
    }
  },

  // Уведомления
  async getNotifications(userId) {
    try {
      const notifications = await db.all(`
        SELECT * FROM notifications 
        WHERE userId = ?
        ORDER BY createdAt DESC
        LIMIT 50
      `, userId);

      return { status: 200, body: { notifications } };
    } catch (error) {
      return handleError(error, 'Failed to get notifications');
    }
  },

  // Настройки пользователя
  async updateSettings(userId, { language, theme }) {
    try {
      await db.run(`
        UPDATE users 
        SET language = ?, theme = ?
        WHERE id = ?
      `, language, theme, userId);

      return { status: 200, body: { success: true } };
    } catch (error) {
      return handleError(error, 'Failed to update settings');
    }
  },

  // Задачи
  async createTask({ title, description, priority, dueDate, workspaceId, creatorId }) {
    try {
      const taskId = uuidv4();
      await db.run(`
        INSERT INTO tasks (id, title, description, priority, dueDate, workspaceId, creatorId)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `, taskId, title, description, priority, dueDate, workspaceId, creatorId);

      return { status: 201, body: { taskId } };
    } catch (error) {
      return handleError(error, 'Failed to create task');
    }
  }
};
