import { Pool } from 'pg';
import { getDatabaseUri } from './config';

const databaseUri = getDatabaseUri();

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: databaseUri,
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT || '5432'),
});

export default pool;