const { check } = require('express-validator');

exports.signupValidation = [
    check('nume', 'Numele este obligatoriu').not().isEmpty(),
    check('email', 'Email-ul trebuie sa fie valid').isEmail(),
    check('password', 'Parola trebuie sa aiba minim 6 caractere').isLength({ min: 6 })
]

exports.loginValidation = [
    check('email', 'Email-ul trebuie sa fie valid').isEmail(),
    check('password', 'Parola trebuie sa aiba minim 6 caractere').isLength({ min: 6 })
]

exports.cnpValidation = [
    check('cnp').optional().isLength({ min: 13 }).withMessage('CNP-ul trebuie sa aiba 13 caractere')
]
