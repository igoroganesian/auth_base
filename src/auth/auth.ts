import express, { Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { JWT_SECRET } from '../config';
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
        return res.status(409).send('User already exists');
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

authRouter.post('/login', async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;

    const userResult = await pool.query(
      `SELECT * FROM users WHERE username = $1`,
      [username]);

    if (userResult.rows.length === 0) {
      return res.status(401).send('User not found');
    }

    const user = userResult.rows[0];

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).send('Invalid password');
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token: token });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

export default authRouter;