function getDatabaseUri() {
  return process.env.NODE_ENV === 'test'
    ? process.env.TEST_DATABASE_URL || 'postgresql:///authbase_test'
    : process.env.DATABASE_URL || 'postgresql:///authbase';
}

// necessary for TypeScript to accept the JWT in auth.ts
function getEnvVariable(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Environment variable ${key} is not set`);
  }
  return value;
}

const JWT_SECRET = getEnvVariable('JWT_SECRET');

export { getDatabaseUri, JWT_SECRET };