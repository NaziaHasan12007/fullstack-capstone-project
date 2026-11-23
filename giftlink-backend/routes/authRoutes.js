//Step 1 - Task 2: Import necessary packages
const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const connectToDatabase = require('../models/db');
const router = express.Router();
const dotenv = require('dotenv');
const pino = require('pino');

//Step 1 - Task 3: Create a Pino logger instance
const logger = pino();

dotenv.config();

//Step 1 - Task 4: Create JWT secret
const JWT_SECRET = process.env.JWT_SECRET;

router.post(
    '/register',
    [
        body('firstName', 'First name is required').trim().notEmpty(),
        body('lastName', 'Last name is required').trim().notEmpty(),
        body('email', 'Please enter a valid email address').isEmail().normalizeEmail(),
        body('password', 'Password must be at least 6 characters').isLength({ min: 6 }),
    ],
    async (req, res) => {
        //Step 2: Validate input, check existing user, hash password, save user, and issue JWT
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.error({ errors: errors.array() }, 'Registration validation failed');
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const db = await connectToDatabase();
            const collection = db.collection('users');

            const existingEmail = await collection.findOne({ email: req.body.email });
            if (existingEmail) {
                logger.warn({ email: req.body.email }, 'Registration failed: Email already exists');
                return res.status(400).json({ error: 'Email already exists' });
            }

            const salt = await bcryptjs.genSalt(10);
            const hash = await bcryptjs.hash(req.body.password, salt);

            const newUser = await collection.insertOne({
                email: req.body.email,
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                password: hash,
                createdAt: new Date(),
            });

            const payload = {
                user: {
                    id: newUser.insertedId,
                },
            };

            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info({ email: req.body.email }, 'User registered successfully');

            return res.status(201).json({ authtoken, email: req.body.email });
        } catch (error) {
            logger.error({ err: error.message }, 'Internal server error during registration');
            return res.status(500).send('Internal server error');
        }
    }
);

module.exports = router;