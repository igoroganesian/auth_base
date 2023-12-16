import express from 'express';
import bcrypt from 'bcryptjs';
import pool from '../db';

const router = express.Router();

router.post('/signup', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    let errorMessage = '';

    if (!username) {
      errorMessage += 'Username is required. ';
    }

    if (!password) {
      errorMessage += 'Password is required. ';
    } else if (password.length < 8) {
      errorMessage += 'Password must be at least 8 characters long. ';
    }

    if (!email) {
      errorMessage += 'Email is required. ';
    } else if (!email.includes('@')) {
      errorMessage += 'Email is invalid. ';
    }

    if (errorMessage) {
      return res.status(400).send(errorMessage.trim());
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    // check for existing user /+ insert into db
    res.status(201).send('Signup successful');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});