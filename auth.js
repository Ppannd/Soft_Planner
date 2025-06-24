
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';


let db;
async function initDB() {
  db = await open({
    filename: './database.db',
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      language TEXT DEFAULT 'en',
      theme TEXT DEFAULT 'dark',
      avatar TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS workspaces (
      id TEXT PRIMARY KEY,
      name TEXT,
      owner_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(owner_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS workspace_members (
      workspace_id TEXT,
      user_id TEXT,
      role TEXT DEFAULT 'member',
      PRIMARY KEY (workspace_id, user_id),
      FOREIGN KEY(workspace_id) REFERENCES workspaces(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      title TEXT,
      description TEXT,
      priority TEXT CHECK(priority IN ('low', 'medium', 'high')),
      due_date TEXT,
      completed BOOLEAN DEFAULT 0,
      workspace_id TEXT,
      creator_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(workspace_id) REFERENCES workspaces(id),
      FOREIGN KEY(creator_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS invitations (
      id TEXT PRIMARY KEY,
      workspace_id TEXT,
      sender_id TEXT,
      recipient_id TEXT,
      status TEXT CHECK(status IN ('pending', 'accepted', 'rejected')) DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(workspace_id) REFERENCES workspaces(id),
      FOREIGN KEY(sender_id) REFERENCES users(id),
      FOREIGN KEY(recipient_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      type TEXT CHECK(type IN ('invitation', 'task', 'system')),
      message TEXT,
      is_read BOOLEAN DEFAULT 0,
      related_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);
}

initDB();


class AppError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.statusCode = statusCode;
  }
}


export default {

  async register({ name, email, password }) {
    try {

      if (!name || !email || !password) {
        throw new AppError('Все поля обязательны');
      }

      if (password.length < 8) {
        throw new AppError('Пароль должен быть не менее 8 символов');
      }

 
      const existingUser = await db.get('SELECT id FROM users WHERE email = ?', email);
      if (existingUser) {
        throw new AppError('Пользователь с таким email уже существует');
      }

  
      const hashedPassword = await bcrypt.hash(password, 10);
      const userId = uuidv4();

      await db.run(
        'INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)',
        userId, name, email, hashedPassword
      );

      // Создание личного рабочего пространства
      const workspaceId = uuidv4();
      await db.run(
        'INSERT INTO workspaces (id, name, owner_id) VALUES (?, ?, ?)',
        workspaceId, `${name}'s Workspace`, userId
      );

      await db.run(
        'INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)',
        workspaceId, userId, 'owner'
      );

      return {
        statusCode: 201,
        body: { 
          success: true,
          user: { id: userId, name, email }
        }
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || 500,
        body: { error: error.message || 'Ошибка сервера' }
      };
    }
  },

 
  async login({ email, password }) {
    try {

      if (!email || !password) {
        throw new AppError('Email и пароль обязательны');
      }

    
      const user = await db.get('SELECT * FROM users WHERE email = ?', email);
      if (!user) {
        throw new AppError('Неверный email или пароль', 401);
      }

   
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        throw new AppError('Неверный email или пароль', 401);
      }

  
      const { password: _, ...userData } = user;
      return {
        statusCode: 200,
        body: { 
          success: true, 
          user: userData 
        }
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || 500,
        body: { error: error.message || 'Ошибка сервера' }
      };
    }
  },

  async sendInvitation({ senderId, recipientEmail, workspaceId }) {
    try {
      const isMember = await db.get(
        `SELECT role FROM workspace_members 
         WHERE workspace_id = ? AND user_id = ?`,
        workspaceId, senderId
      );

      if (!isMember || isMember.role !== 'owner') {
        throw new AppError('Недостаточно прав', 403);
      }
      const recipient = await db.get(
        'SELECT id FROM users WHERE email = ?',
        recipientEmail
      );

      if (!recipient) {
        throw new AppError('Пользователь не найден', 404);
      }

      const existingInvite = await db.get(
        `SELECT id FROM invitations 
         WHERE workspace_id = ? AND recipient_id = ? AND status = 'pending'`,
        workspaceId, recipient.id
      );

      if (existingInvite) {
        throw new AppError('Приглашение уже отправлено');
      }

      const invitationId = uuidv4();
      await db.run(
        `INSERT INTO invitations 
         (id, workspace_id, sender_id, recipient_id) 
         VALUES (?, ?, ?, ?)`,
        invitationId, workspaceId, senderId, recipient.id
      );

      const notificationId = uuidv4();
      const workspace = await db.get(
        'SELECT name FROM workspaces WHERE id = ?',
        workspaceId
      );

      await db.run(
        `INSERT INTO notifications 
         (id, user_id, type, message, related_id) 
         VALUES (?, ?, ?, ?, ?)`,
        notificationId, 
        recipient.id, 
        'invitation', 
        `Вас пригласили в рабочее пространство "${workspace.name}"`,
        invitationId
      );

      return {
        statusCode: 201,
        body: { success: true }
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || 500,
        body: { error: error.message || 'Ошибка сервера' }
      };
    }
  },

  async getNotifications(userId) {
    try {
      const notifications = await db.all(
        `SELECT * FROM notifications 
         WHERE user_id = ? 
         ORDER BY created_at DESC
         LIMIT 50`,
        userId
      );

      await db.run(
        'UPDATE notifications SET is_read = 1 WHERE user_id = ?',
        userId
      );

      return {
        statusCode: 200,
        body: { notifications }
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || 500,
        body: { error: error.message || 'Ошибка сервера' }
      };
    }
  },

  async updateSettings(userId, { language, theme, avatar }) {
    try {
      await db.run(
        `UPDATE users 
         SET language = ?, theme = ?, avatar = ?
         WHERE id = ?`,
        language, theme, avatar, userId
      );

      return {
        statusCode: 200,
        body: { success: true }
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || 500,
        body: { error: error.message || 'Ошибка сервера' }
      };
    }
  },

  async getWorkspaces(userId) {
    try {
      const workspaces = await db.all(
        `SELECT w.* FROM workspaces w
         JOIN workspace_members m ON w.id = m.workspace_id
         WHERE m.user_id = ?`,
        userId
      );

      return {
        statusCode: 200,
        body: { workspaces }
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || 500,
        body: { error: error.message || 'Ошибка сервера' }
      };
    }
  },

  
  async createTask({ title, description, priority, dueDate, workspaceId, creatorId }) {
    try {
      
      if (!title || !workspaceId || !creatorId) {
        throw new AppError('Обязательные поля: title, workspaceId, creatorId');
      }

      const taskId = uuidv4();
      await db.run(
        `INSERT INTO tasks 
         (id, title, description, priority, due_date, workspace_id, creator_id) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        taskId, title, description, priority, dueDate, workspaceId, creatorId
      );

      return {
        statusCode: 201,
        body: { taskId }
      };
    } catch (error) {
      return {
        statusCode: error.statusCode || 500,
        body: { error: error.message || 'Ошибка сервера' }
      };
    }
  }
};
