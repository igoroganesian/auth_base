import express from 'express';

const app = express();

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Auth Base');
});

export default app;