const dotenv = require('dotenv');
dotenv.config();
const nodemailer = require('nodemailer');
const transport = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.NODEMAILER_EMAIL,
    pass: process.env.NODEMAILER_PASSWORD
  }
});
const { Router } = require('express');
const router = new Router();

const User = require('./../models/user');
const bcryptjs = require('bcryptjs');

const generateRandomToken = length => {
  const characters =
    '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let token = '';
  for (let i = 0; i < length; i++) {
    token += characters[Math.floor(Math.random() * characters.length)];
  }
  return token;
};

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/sign-up', (req, res, next) => {
  res.render('sign-up');
});

router.post('/sign-up', (req, res, next) => {
  const { name, email, password } = req.body;
  const token = generateRandomToken(10);
  let user;
  bcryptjs
    .hash(password, 10)
    .then(hash => {
      return User.create({
        name,
        email,
        passwordHash: hash,
        confirmationToken: token
      });
    })
    .then(newUser => {
      user = newUser;
      return transport.sendMail({
        from: process.env.NODEMAILER_EMAIL,
        to: email,
        subject: 'Email verification',
        html: `<a href="http://localhost:3000/auth/confirm-email?token=${token}">Verify your email</a>`
      });
    })
    .then(result => {
      req.session.user = user._id;
      res.redirect('/');
      console.log('Email was sent successfully.');
      console.log(result);
    })
    .catch(error => {
      next(error);
    });
});

router.get('/auth/confirm-email/', (req, res, next) => {
  const emailToken = req.query.token;
  User.findOneAndUpdate(
    { confirmationToken: emailToken },
    { status: 'active' },
    { new: true }
  )
    .then(user => {
      req.session.user = user._id;
      req.session.user = user.token;
      res.render('confirmation', { user });
      console.log('Email was confirmed successfully!');
      console.log(user);
    })
    .catch(error => {
      next(error);
    });
});

router.get('/sign-in', (req, res, next) => {
  res.render('sign-in');
});

router.post('/sign-in', (req, res, next) => {
  let userId;
  const { email, password } = req.body;
  User.findOne({ email })
    .then(user => {
      if (!user) {
        return Promise.reject(new Error("There's no user with that email."));
      } else {
        userId = user._id;
        return bcryptjs.compare(password, user.passwordHash);
      }
    })
    .then(result => {
      if (result) {
        req.session.user = userId;
        res.redirect('/');
      } else {
        return Promise.reject(new Error('Wrong password.'));
      }
    })
    .catch(error => {
      next(error);
    });
});

router.post('/sign-out', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

const routeGuard = require('./../middleware/route-guard');
const { token } = require('morgan');

router.get('/private', routeGuard, (req, res, next) => {
  res.render('profile');
});

module.exports = router;
