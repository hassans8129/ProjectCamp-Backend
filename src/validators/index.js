import { body } from 'express-validator';

const userRegisterValidator = () => {
  return [
    body('email')
      .trim()
      .notEmpty()
      .withMessage('Email is  required!')
      .isEmail()
      .withMessage('Email is invalid'),

    body('username')
      .trim()
      .notEmpty()
      .withMessage('Username is required')
      .isLowercase()
      .withMessage('username is required')
      .isLength({ min: 3 })
      .withMessage('Username must be atleast 3 characters long'),

    body('password').trim().notEmpty().withMessage('Password is required'),

    body('fullName').optional().trim(),
  ];
};

const userLoginInValidator = () => {
  return [
    body('email').optional().isEmail().withMessage('Email is invalid'),
    body('password').notEmpty().withMessage('Password is required'),
  ];
};

const userChangeCurrentPasswordValidator = () => {
  return [
    body('oldPassword').notEmpty().withMessage('Old password is required'),
    body('newPassword').notEmpty().withMessage('New password is required'),
  ];
};

const userForgotPasswordValidator = () => {
  return [
    body('email')
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Email is invalid'),
  ];
};

const userResetForgotPasswordValidator = () => {
  return [body('newPassword').notEmpty().withMessage('Password is required')];
};

export {
  userRegisterValidator,
  userLoginInValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
};
