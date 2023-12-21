import request from 'supertest';
import express from 'express';
import pool from '../src/db';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { JWT_SECRET } from '../src/config';
import authRouter from '../src/auth/authRouter';

const app = express();
app.use(express.json());
app.use('/auth', authRouter);

describe('Auth Routes', () => {
  beforeAll(async () => {
    const password = 'password123';
    const hashedPassword = await bcrypt.hash(password, 12);
    await pool.query(`INSERT INTO users (email, password) VALUES ($1, $2)`,
      ['test@email.com', hashedPassword]);
  });

  afterAll(async () => {
    await pool.query('DELETE FROM users');
  });

  /** SIGNUP TESTS */
  describe('POST /auth/signup', () => {
    it('should create a new user with valid credentials', async () => {
      const res = await request(app)
        .post('/auth/signup')
        .send({
          email: 'newuser@email.com',
          password: 'password123'
        });
      expect(res.statusCode).toEqual(201);
      expect(res.text).toEqual('Signup successful');
    });

    it('should reject signup with an existing email', async () => {
      const res = await request(app)
        .post('/auth/signup')
        .send({
          email: 'test@email.com',
          password: 'password123'
        });
      expect(res.statusCode).toEqual(409);
      expect(res.text).toContain('User already exists');
    });

    it('should reject signup with an invalid email format', async () => {
      const res = await request(app)
        .post('/auth/signup')
        .send({
          email: 'testemail.com',
          password: 'password123'
        });
      expect(res.statusCode).toEqual(400);
      expect(res.text).toContain('Invalid email');
    });

    it('should reject signup if password too short', async () => {
      const res = await request(app)
        .post('/auth/signup')
        .send({
          email: 'test@email.com',
          password: 'pass'
        });
      expect(res.statusCode).toEqual(400);
      expect(res.text).toContain('Password must be at least 8 characters long');
    });
  });

  /** LOGIN TESTS */
  describe('POST /auth/login', () => {
    it('should authenticate user and return a token', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({
          email: 'test@email.com',
          password: 'password123'
        });
      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty('token');
    });

    it('should return a valid JWT with successful login', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: 'test@email.com', password: 'password123' });
      expect(res.statusCode).toEqual(200);

      const token = res.body.token;
      expect(token).toBeDefined();
      const parts = token.split('.');
      expect(parts.length).toEqual(3);

      let decoded;
      try {
        decoded = jwt.verify(token, JWT_SECRET);
      } catch (error) {
        decoded = null;
      }
      expect(decoded).toBeDefined();
      expect(decoded).toHaveProperty('userId');
      expect(decoded).toHaveProperty('email', 'test@email.com');
    });

    it('should reject login with invalid email', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({
          email: 'testemail.com',
          password: 'password123'
        });
      expect(res.statusCode).toEqual(401);
      expect(res.text).toContain('User not found');
    });

    it('should reject login with invalid password', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({
          email: 'test@email.com',
          password: 'pass'
        });
      expect(res.statusCode).toEqual(401);
      expect(res.text).toContain('Invalid password');
    });
  });

});
