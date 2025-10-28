import { User } from '../models/user.models.js';
import { ApiError } from '../utils/Api_error.js';
import { ApiResponse } from '../utils/Api_response.js';
import { asyncHandler } from '../utils/async-handler.js';
import { emailaVerificationMailgenContent, sendEmail } from '../utils/mail.js';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { validateHeaderName } from 'http';
import { validationResult } from 'express-validator';

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      'Something went wrong while generating access token!',
    );
  }
};

// const generateAccessAndRefreshToken = async (userId) => {
//   try {
//     console.log('🔹 Received userId:', userId);

//     const user = await User.findById(userId);
//     console.log('🔹 User found:', user);

//     if (!user) {
//       throw new ApiError(404, 'User not found for token generation');
//     }

//     if (typeof user.generateAccessToken !== 'function') {
//       throw new ApiError(
//         500,
//         'generateAccessToken() is NOT defined in User model',
//       );
//     }
//     if (typeof user.generateRefreshToken !== 'function') {
//       throw new ApiError(
//         500,
//         'generateRefreshToken() is NOT defined in User model',
//       );
//     }

//     const accessToken = user.generateAccessToken();
//     const refreshToken = user.generateRefreshToken();
//     console.log('🔹 Tokens generated:', { accessToken, refreshToken });

//     user.refreshToken = refreshToken;
//     await user.save({ validateBeforeSave: false });
//     return { accessToken, refreshToken };
//   } catch (error) {
//     console.error('❌ REAL ERROR:', error);
//     throw new ApiError(
//       500,
//       error.message || 'Something went wrong while generating access token!',
//     );
//   }
// };

const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  const existedUser = await User.findOne({
    $or: [{ username }, { email }], // FINDING IF THE USER ALREADY EXISTS OR NOT BY USERNAME OR EMAIL
  });

  if (existedUser) {
    throw new ApiError(409, 'User with email or username already exists! ', []); // IF YES THEN THROW THIS ERROR
  }

  const user = await User.create({
    // SAVING THIS USER TO DATABASE, ONCE OPERATION HAS BEEN PERFORMED -DATA IS STORED IN USER-
    email,
    password,
    username,
    isEmailVerified: false,
  });

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: 'Please verify your email',
    mailgenContent: emailaVerificationMailgenContent(
      user.username,
      `${req.protocol}://${req.get('host')}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  const createdUser = await User.findById(user._id).select(
    '-password -refreshToken -emailVerificationToken -emailVarificationExpiry',
  );

  if (!createdUser) {
    throw new ApiError(500, 'Something went wrong while registrating a user');
  }

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { user: createdUser },
        'User registered successfully and verification email has been sent on your email!',
      ),
    );
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    throw new ApiError(400, 'Email is required!');
  }

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(400, 'User  does not exist!');
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(400, 'Invalid credentials');
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id,
  );

  const loggedInUser = await User.findById(user._id).select(
    '-password -refreshToken -emailVerificationToken -emailVarificationExpiry',
  );

  const options = {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
  };

  return res
    .status(200)
    .cookie('accessToken', accessToken, options)
    .cookie('refreshToken', refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        'User logged in succesfully!',
      ),
    );
});

const logOutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: '', // IF WE WANT WE CAN ALSO DEFINE NULL OR UNDEFINES, BUT EMTY IS ALSO FINE
      },
    },
    {
      new: true, // ONCE EVERYTHING IS DONE, GIVES THE MORE UPDATED OR NEWER OBJECT
    },
  );

  const options = {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // true only if you're using HTTPS
  };

  return res
    .status(200)
    .clearCookie('accessToken', options) // TO CLEAR COOKIES OPTIONS MUST MATCH OR IT WILL NOT BE CLEARED
    .clearCookie('refreshToken', options)
    .json(new ApiResponse(200, {}, 'User logged out!')); // {} THIS MEANS IT NOT SENDING ANY DATA
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, 'Current user fetched successfully'));
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params; // REQ.PARAMS GIVES ACCESS TO URL ITSELF

  if (!verificationToken) {
    throw new ApiError(400, 'Email verifcation is missing');
  }

  let hashedToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(400, 'Token is invalid or expired');
  }

  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;

  user.isEmailVerified = true;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, { isEmailVerified: true }, 'Email is verified'));
});

const resendEmailVerification = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user?._id);

  if (!user) {
    throw new ApiError(404, 'User not found');
  }

  if (user.isEmailVerified) {
    throw new ApiError(409, 'User is already verified');
  }

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: 'Please verify your email',
    mailgenContent: emailaVerificationMailgenContent(
      user.username,
      `${req.protocol}://${req.get('host')}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, 'Mail has been sent to your Email id'));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, 'Unauthorized acccess');
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET,
    );

    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, 'Invalid refresh token');
    }

    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, 'refresh token is expired');
    }

    const options = {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
    };

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessAndRefreshToken(user._id); //DONT JUST SEND THIS DATA, UPADATE THE REFRESH TOKEN AS WELL (COMMON MISTAKE)

    user.refreshToken = newRefreshToken;

    await user.save();

    return res
      .status(200)
      .cookie('accessToken', accessToken, options)
      .cookie('refreshToken', newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          {
            accessToken,
            refreshToken: newRefreshToken,
          },
          'Access token refresh',
        ),
      );
  } catch (error) {
    throw new ApiError(401, 'Invalid refresh token');
  }
});

const forgotPasswordRequest = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(404, 'User not found', []);
  }

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.forgotPasswordToken = hashedToken;
  user.forgotPasswordExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: 'Password reset request',
    mailgenContent: emailaVerificationMailgenContent(
      user.username,
      `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        'Password reset email has been sent to your mail id',
      ),
    );
});

const resetForgotPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  let hashedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(489, 'Token is invalid or expired');
  }

  user.forgotPasswordToken = undefined;
  user.forgotPasswordExpiry = undefined;

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, 'Password reset successfully'));
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user?._id);

  const isPasswordValid = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordValid) {
    throw new ApiError(400, 'Invalid old password');
  }

  user.password = newPassword;

  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, 'Password has been updates'));
});

export {
  registerUser,
  login,
  logOutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  forgotPasswordRequest,
  resetForgotPassword,
  changeCurrentPassword,
};
