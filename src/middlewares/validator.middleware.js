import { validationResult } from 'express-validator';
import { ApiError } from '../utils/Api_error.js';

export const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }

  const extractedErrors = [];

  errors.array().map(
    (
      err, // WITH .map()  WE'RE MAKING SURE THAT IT IS AN ARRAY
    ) =>
      extractedErrors.push({
        [err.path]: err.msg, // PUSHING IN LIKE AN OBJECT, SO THAT WE GET THE PATH AS WELL AS ERROR MESSAGE
      }),
  );
  throw new ApiError(422, 'Recived data is not valid!');
};
