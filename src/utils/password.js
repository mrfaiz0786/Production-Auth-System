import argon2 from 'argon2';

// Argon2id options for password hashing
const hashOptions = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16, // 64MB
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
  saltLength: 16,
};

export const hashPassword = async (password) => {
  if (!password) {
    throw new Error('Password is required');
  }
  
  return await argon2.hash(password, hashOptions);
};

export const verifyPassword = async (password, hash) => {
  if (!password || !hash) {
    return false;
  }
  
  try {
    return await argon2.verify(hash, password);
  } catch (err) {
    return false;
  }
};