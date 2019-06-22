// * ==================== DEPENDENCIES ==================== *//

// * Bring in JWT - read about json web tokens here https://jwt.io/
const jwt = require('jsonwebtoken');

// * Bring in your dotenv where you were store your JWT Secret
const config = require('dotenv').config();

// * ==================== FUNCTION ==================== *//

// * In this middleware you will verify that the API token passed into the API request header is valid, and then return something (i.e., your user information) and store it in the request to be used by your controller

module.exports = function(req, res, next) {
  // * Get token from API request header
  const token = req.header('x-auth-token');

  // * Check if no token...
  if (!token) {
    return res.status(401).json({ msg: 'No token, authorization denied' });
  }

  // * Verify token...
  try {
    // * ...by using your JWT Secret
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // * Attach information you want to pass on to your req
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};
