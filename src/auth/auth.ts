import express, { Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcryptjs';
import pool from '../db';

const authRouter = express.Router();

authRouter.post('/signup',
  [
    body('username', 'Username is required').notEmpty(),
    body('email', 'Invalid email').isEmail(),
    body('password', 'Password must be at least 8 characters long').isLength({ min: 8 })
  ],
  async (req: Request, res: Response) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { username, password, email } = req.body;

      const existingUser = await pool.query(
        `SELECT * FROM users WHERE username = $1 OR email = $2`,
        [username, email]);

      if (existingUser.rows.length > 0) {
        return res.status(409).send('User already exists.');
      }

      const hashedPassword = await bcrypt.hash(password, 12);

      await pool.query(
        `INSERT INTO users (username, password, email) VALUES ($1, $2, $3)`,
        [username, hashedPassword, email]);

      res.status(201).send('Signup successful');
    } catch (error) {
      console.error(error);
      res.status(500).send('Server error');
    }
  });

export default authRouter;