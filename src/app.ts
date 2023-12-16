import express from 'express';
import authRouter from './auth/auth';

const app = express();

app.use(express.json());

app.use('/auth', authRouter);

app.get('/', (req, res) => {
  res.send('Auth Base');
});

export default app;