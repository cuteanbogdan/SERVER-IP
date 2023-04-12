const express = require('express');
const router = express.Router();
const db = require('./db.js');
const bcrypt = require('bcrypt');
const { uuid } = require('uuidv4');
const nodemailer = require('nodemailer');

//send email
function sendEmail(email, token) {

    var email = email;
    var token = token;

    var mail = nodemailer.createTransport({
        service: 'yahoo',
        auth: {
            user: 'cutybogdy@yahoo.com', // Your email id
            pass: 'dbyvstclmtlnkord' // Your password
        }
    });

    var mailOptions = {
        from: 'cutybogdy@yahoo.com',
        to: email,
        subject: 'Reset Password Link - SmartCare.com',
        html: '<p>You requested for reset password, kindly use this <a href="http://localhost:3000/update-password?token=' + token + '">link</a> to reset your password</p>'

    };

    mail.sendMail(mailOptions, function (error, info) {
        if (error) {
            console.log(1)
        } else {
            console.log(0)
        }
    });
}
/* send reset password link in email */
router.post('/change-password-email', function (req, res, next) {
    const email = req.body.email;

    db.query('SELECT * FROM users_database WHERE email ="' + email + '"', function (err, result) {
        if (err) throw err;

        if (result[0].email.length > 0) {
            var changePasswordToken = uuid();
            var sent = sendEmail(email, changePasswordToken);

            if (sent != '0') {
                var data = {
                    changePasswordToken: changePasswordToken
                };

                db.query('UPDATE users_database SET ? WHERE email ="' + email + '"', data, function (err, result) {
                    if (err) throw err;
                });

                res.status(200).json({
                    status: 'success',
                    message: 'The reset password link has been sent to your email address'
                });
            } else {
                res.status(500).json({
                    status: 'error',
                    message: 'Something went wrong. Please try again'
                });
            }
        } else {
            res.status(404).json({
                status: 'error',
                message: 'The Email is not registered with us'
            });
        }
    });
});

/* update password to database */
router.post('/update-password', function (req, res, next) {
    const token = req.body.token;
    const password = req.body.password;

    db.query('SELECT * FROM users_database WHERE changePasswordToken ="' + token + '"', function (err, result) {
        if (err) throw err;

        if (result.length > 0) {
            var saltRounds = 10;
            bcrypt.genSalt(saltRounds, function (err, salt) {
                bcrypt.hash(password, salt, function (err, hash) {
                    var data = {
                        password: hash
                    };

                    db.query('UPDATE users_database SET ? WHERE email ="' + result[0].email + '"', data, function (err, result) {
                        if (err) throw err;
                    });

                    res.status(200).json({
                        status: 'success',
                        message: 'Your password has been updated successfully'
                    });
                });
            });
        } else {
            res.status(400).json({
                status: 'error',
                message: 'Invalid link; please try again'
            });
        }
    });
});

module.exports = router;