// * ==================== DEPENDENCIES ==================== *//
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs'); // * to encrypt user passwords
const jwt = require('jsonwebtoken');
const config = require('dotenv').config();
const { check, validationResult } = require('express-validator/check'); // * use express-validate to handle validation and responses
const User = require('/your/user/model');

// * ==================== ROUTE ==================== *//

// * @route   POST api/users
// * @desc    Register user
// * @access  Public
router.post(
  '/',
  [
    // ! express-validate functions to validate request body START
    // ! see express-validate docs for more info
    check('name', 'Please enter your full name')
      .not()
      .isEmpty(),
    check('email', 'Please enter a valid email address').isEmail(),
    check(
      'password',
      'Please enter a password with 8 or more characters'
    ).isLength({ min: 8 })
    // ! express-validate functions to validate request body END
  ],
  async (req, res) => {
    // ! express-validate error catching START
    // ! see express-validate docs for more info
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array()
      });
    }
    // ! express-validate error catching END

    // * Destructure req.body
    const { name, email, password } = req.body;

    try {
      // * See if user exists
      let user = await User.findOne({
        email
      });

      if (user) {
        return res.status(400).json({
          errors: [
            {
              msg: 'User already exists'
            }
          ]
        });
      }

      // * Create an instance of the user
      user = new User({
        name,
        email,
        password
      });

      // * Encrypt password with bcrypt
      const salt = await bcrypt.genSalt(10);

      user.password = await bcrypt.hash(password, salt);

      // * Save user to database
      await user.save();

      // * Return jsonwebtoken
      const payload = {
        user: {
          id: user.id /* insert any other information you want in the payload */
        }
      };
      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        {
          expiresIn: 360000 /* in seconds, change to fit your needs */
        },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

module.exports = router;
