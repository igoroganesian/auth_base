function getDatabaseUri() {
  return process.env.NODE_ENV === 'test'
    ? process.env.TEST_DATABASE_URL || 'postgresql:///authbase_test'
    : process.env.DATABASE_URL || 'postgresql:///authbase';
}

export { getDatabaseUri };