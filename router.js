const express = require('express');
const router = express.Router();
const db = require('./db.js');
const { signupValidation, loginValidation } = require('./validation');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const roles = {
    "Administrator": "Administrator",
    "Pacient": "Pacient",
    "Medic": "Medic",
    "Ingrijitor": "Ingrijitor",
    "Supraveghetor": "Supraveghetor"
}

const checkTokenExistence = (req, res, next) => {
    if (
        !req.headers.authorization ||
        !req.headers.authorization.startsWith('Bearer') ||
        !req.headers.authorization.split(' ')[1]
    ) {
        return res.status(422).json({
            message: "Please provide the token",
        });
    }
}

router.post('/register', signupValidation, (req, res, next) => {
    try {
        db.query(
            `SELECT * FROM users_database WHERE LOWER(email) = LOWER(${db.escape(
                req.body.email
            )});`,
            (err, result) => {
                if (result.length) {
                    return res.status(409).send({
                        msg: 'This user is already in use!'
                    });
                } else {
                    // username is available
                    bcrypt.hash(req.body.password, 10, (err, hash) => {
                        if (err) {
                            return res.status(500).send({
                                msg: err
                            });
                        } else {
                            // has hashed pw => add to database
                            db.query(
                                `INSERT INTO users_database (name, email, password, role) VALUES ('${req.body.name}', ${db.escape(
                                    req.body.email
                                )}, ${db.escape(hash)}, ${db.escape(roles[req.body.role])})`,
                                (err, result) => {
                                    if (err) {
                                        return res.status(400).send({
                                            msg: err
                                        });
                                    }
                                    return res.status(201).send({
                                        msg: 'The user has been registerd with us!'
                                    });
                                }
                            );
                        }
                    });
                }
            }
        );
    } catch (err) {
        console.log(err)
    }

});

router.post('/login', loginValidation, (req, res, next) => {
    db.query(
        `SELECT * FROM users_database WHERE email = ${db.escape(req.body.email)};`,
        (err, result) => {
            // user does not exists
            if (err) {
                return res.status(400).send({
                    msg: err
                });
            }
            if (!result.length) {
                return res.status(401).send({
                    msg: 'Email or password is incorrect!'
                });
            }
            // check password
            bcrypt.compare(
                req.body.password,
                result[0]['password'],
                (bErr, bResult) => {
                    // wrong password
                    if (bErr) {
                        return res.status(401).send({
                            msg: 'Email or password is incorrect!'
                        });
                    }
                    if (bResult) {
                        let payload = { id: result[0].id, email: result[0].email, role: result[0].role }
                        const token = jwt.sign(payload, process.env.JWT_SECRET, { issuer: 'http://cuty.com', expiresIn: '24h' });
                        return res.status(200).send({
                            msg: 'Logged in!',
                            token,
                            user: result[0]
                        });
                    }
                    return res.status(401).send({
                        msg: 'Email or password is incorrect!'
                    });
                }
            );
        }
    );
});

router.post('/get-user', (req, res, next) => {
    checkTokenExistence(req, res, next)
    const theToken = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(theToken, process.env.JWT_SECRET);
    db.query('SELECT * FROM users where id=?', decoded.id, function (error, results, fields) {
        if (error) throw error;
        return res.send({ error: false, data: results[0], message: 'Fetch Successfully.' });
    });
});

router.post('/getallusers', (req, res, next) => {
    checkTokenExistence(req, res, next)
    db.query('SELECT * FROM users_database', function (error, results, fields) {
        if (error) console.log(error);
        return res.status(200).send({ error: false, data: results, message: 'Fetch Successfully.' });
    });
});

router.put('/update-user-role/:id', (req, res) => {
    checkTokenExistence(req, res);
    const userId = req.params.id;
    const { role } = req.body;
    db.query('UPDATE users_database SET role = ? WHERE id = ?', [role, userId], (err, result) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ error: true, message: 'Failed to update user role.' });
        }
        return res.status(200).json({ error: false, message: 'User role updated successfully.' });
    });
});


router.post('/delete-user/:id', (req, res, next) => {
    checkTokenExistence(req, res, next);
    const userId = req.params.id;
    db.query('DELETE FROM users_database WHERE id = ?', [userId], function (error, results, fields) {
        if (error) {
            console.log(error);
            return res.status(500).json({ error: true, message: 'Failed to delete user.' });
        }
        return res.status(200).send({ error: false, message: 'User deleted successfully.' });
    });
});


router.post('/getutilizator/:id', (req, res, next) => {
    checkTokenExistence(req, res, next)
    const theToken = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(theToken, process.env.JWT_SECRET);
    db.query('SELECT * FROM users where id=?', req.params.id, function (error, results, fields) {
        if (error) throw error;
        return res.send({ error: false, data: results[0], message: 'Fetch Successfully.' });
    });
});

router.post('/verifytoken', (req, res, next) => {
    checkTokenExistence(req, res, next)
    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {

        if (err) {
            let stringErr = err.toString()
            if (stringErr.includes("jwt expired"))
                return res.status(422).json({
                    message: "Token has expired, please login again!",
                });
        } else {
            if (decoded.iss != 'http://cuty.com')
                return res.status(422).json({
                    message: "Please provide an original token",
                });
        }
        if (decoded) {
            return res.status(200).json({
                msg: "Token is valid",
                token: decoded,
            });
        } else {
            return res.status(422).json({
                message: "The token is not working",
            });
        }

    })
})


module.exports = router;