import express from 'express';
import bcrypt from 'bcryptjs';
import pool from '../db';

const router = express.Router();

router.post('/signup', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    // add validation
    const hashedPassword = await bcrypt.hash(password, 12);
    // check for existing user /+ insert into db
    res.status(201).send('Signup successful');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});