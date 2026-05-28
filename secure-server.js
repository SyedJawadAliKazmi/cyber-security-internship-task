const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');

const app = express();

app.use(express.json());
app.use(helmet());

// Winston Logger
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({
      filename: 'security.log'
    })
  ]
});

logger.info('Secure Server Started');

// Dummy user database
const users = [];

// Signup Route
app.post('/signup', async (req, res) => {

  const { email, password } = req.body;

  // Email validation
  if (!validator.isEmail(email)) {
    return res.status(400).send('Invalid Email');
  }

  // Password validation
  if (password.length < 6) {
    return res.status(400).send('Password too short');
  }

  // Password hashing
  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({
    email,
    password: hashedPassword
  });

  logger.info('User Registered');

  res.send('User Registered Successfully');
});

// Login Route
app.post('/login', async (req, res) => {

  const { email, password } = req.body;

  const user = users.find(u => u.email === email);

  if (!user) {
    return res.status(400).send('User not found');
  }

  // Compare password
  const validPassword = await bcrypt.compare(
    password,
    user.password
  );

  if (!validPassword) {
    return res.status(401).send('Invalid Password');
  }

  // JWT Token
  const token = jwt.sign(
    { email: user.email },
    'secretkey123'
  );

  logger.info('User Logged In');

  res.send({
    message: 'Login Successful',
    token
  });
});

app.listen(4000, () => {
  console.log('Secure Server Running on Port 4000');
});