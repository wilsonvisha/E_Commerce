require('dotenv').config()
const jwt = require('jsonwebtoken');

exports.generateToken = (payload, passwordReset = false) => {
    const secretKey = process.env.SECRET_KEY || 'default_secret_key';
    const expiration = passwordReset 
        ? process.env.PASSWORD_RESET_TOKEN_EXPIRATION || '15m' 
        : process.env.LOGIN_TOKEN_EXPIRATION || '1d';

    if (!secretKey) {
        throw new Error('SECRET_KEY is not defined in environment variables');
    }

    return jwt.sign(payload, secretKey, { expiresIn: expiration });
};
