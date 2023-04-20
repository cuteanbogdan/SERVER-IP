const express = require('express');
const router = express.Router();
const db = require('./db.js');
const { signupValidation, loginValidation } = require('./validation.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');

const roles = {
    "Administrator": "Administrator",
    "Pacient": "Pacient",
    "Medic": "Medic",
    "Ingrijitor": "Ingrijitor",
    "Supraveghetor": "Supraveghetor"
}

const checkTokenExistence = (req, res, next) => {
    try {
        if (
            !req.headers.authorization ||
            !req.headers.authorization.startsWith('Bearer') ||
            !req.headers.authorization.split(' ')[1]
        ) {
            return res.status(422).json({
                message: "Please provide the token",
            });
        }
        const token = req.headers.authorization.split(' ')[1];
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                if (err instanceof jwt.TokenExpiredError) {
                    return res.status(422).json({
                        message: "Token has expired, please login again!",
                    });
                }
                return res.status(422).json({
                    message: "The token is not working",
                });
            }

            if (decoded && decoded.iss === 'http://smartcare.com') {
                next();
            } else {
                return res.status(422).json({
                    message: "Please provide an original token",
                });
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};


router.post('/register', signupValidation, checkTokenExistence, (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorMessages = errors.array().map(error => error.msg);
        return res.status(400).json({ errors: errorMessages });
    }
    try {
        switch (req.body.role) {
            case "Administrator": console.log("Administrator")
                break;
            case "Medic": console.log("Medic")
                break;
            case "Pacient": db.query(
                `SELECT * FROM Pacienti WHERE LOWER(email) = LOWER(${db.escape(
                    req.body.email
                )});`,
                (err, result) => {
                    if (result.length) {
                        return res.status(409).send({
                            msg: 'This pacient is already in use!'
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
                                    `INSERT INTO Pacienti (role, cnp, nume, prenume, adresa, nr_tel, nr_tel_pers_contact, email, profesie, loc_munca, password, varsta) VALUES (${db.escape(roles[req.body.role])}, ${db.escape(
                                        req.body.cnp)}, ${db.escape(req.body.nume)}, ${db.escape(req.body.prenume)}, ${db.escape(req.body.adresa)}, ${db.escape(req.body.nr_tel)}, ${db.escape(req.body.nr_tel_pers_contact)}, 
                                        ${db.escape(req.body.email)}, ${db.escape(req.body.profesie)}, ${db.escape(req.body.loc_munca)}, ${db.escape(hash)}, ${db.escape(req.body.varsta)})`,
                                    (err, result) => {
                                        if (err) {
                                            return res.status(400).send({
                                                msg: err
                                            });
                                        }
                                        return res.status(201).send({
                                            msg: 'The user has been registered with us!'
                                        });
                                    }
                                );
                            }
                        });
                    }
                }
            );
                break;
            case "Ingrijitor": console.log("Ingrijitor")
                break;
            case "Supraveghetor": console.log("Supraveghetor")
                break;
            default: db.query(
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
                                    `INSERT INTO users_database (name, email, password, role, age) VALUES ('${req.body.name}', ${db.escape(
                                        req.body.email
                                    )}, ${db.escape(hash)}, ${db.escape(roles[req.body.role])}, ${db.escape(req.body.age)})`,
                                    (err, result) => {
                                        if (err) {
                                            return res.status(400).send({
                                                msg: err
                                            });
                                        }
                                        return res.status(201).send({
                                            msg: 'The user has been registered with us!'
                                        });
                                    }
                                );
                            }
                        });
                    }
                }
            );
                break;
        }

    } catch (err) {
        console.log(err)
    }

});

router.post('/login', loginValidation, (req, res, next) => {
    try {
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
                            const token = jwt.sign(payload, process.env.JWT_SECRET, { issuer: 'http://smartcare.com', expiresIn: '24h' });
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
    } catch (error) {
        console.log(error)
    }

});

router.post('/get-user', checkTokenExistence, (req, res, next) => {
    try {
        const theToken = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(theToken, process.env.JWT_SECRET);
        db.query('SELECT * FROM users where id=?', decoded.id, function (error, results, fields) {
            if (error) {
                console.log(error);
                return res.status(500).json({ error: true, msg: 'Failed to fetch user.' });
            }
            return res.send({ error: false, data: results[0], msg: 'Fetch Successfully.' });
        });
    } catch (error) {
        console.log(error)
    }

});

router.post('/getallusers', checkTokenExistence, (req, res, next) => {
    try {
        db.query('SELECT * FROM users_database', function (error, results, fields) {
            if (error) {
                console.log(error);
                return res.status(500).json({ error: true, msg: 'Failed to fetch users.' });
            }
            return res.status(200).send({ error: false, data: results, msg: 'Fetch Successfully.' });
        });
    } catch (error) {
        console.log(error)
    }
});

router.post('/getallpacients', checkTokenExistence, (req, res, next) => {
    try {
        db.query('SELECT * FROM Pacienti WHERE role = ?', ['Pacient'], function (error, results, fields) {
            if (error) {
                console.log(error);
                return res.status(500).send({ error: true, msg: 'Failed to retrieve data.' });
            }
            return res.status(200).send({ error: false, data: results, msg: 'Fetch Successfully.' });
        });
    } catch (error) {
        console.log(error)
    }
});


router.put('/update-user-role/:id', checkTokenExistence, (req, res) => {
    try {
        const userId = req.params.id;
        const { role } = req.body;
        db.query('UPDATE users_database SET role = ? WHERE id = ?', [role, userId], (err, result) => {
            if (err) {
                console.log(err);
                return res.status(500).json({ error: true, msg: 'Failed to update user role.' });
            }
            return res.status(200).json({ error: false, msg: 'User role updated successfully.' });
        });
    } catch (error) {
        console.log(error)
    }
});


router.post('/delete-user/:id', checkTokenExistence, (req, res, next) => {
    try {
        const userId = req.params.id;
        db.query('DELETE FROM users_database WHERE id = ?', [userId], function (error, results, fields) {
            if (error) {
                console.log(error);
                return res.status(500).json({ error: true, msg: 'Failed to delete user.' });
            }
            return res.status(200).send({ error: false, msg: 'User deleted successfully.' });
        });
    } catch (error) {
        console.log(error)
    }

});

router.post('/delete-pacient/:id', checkTokenExistence, (req, res, next) => {
    try {
        const userId = req.params.id;
        db.query('DELETE FROM Pacienti WHERE id_pacient = ?', [userId], function (error, results, fields) {
            if (error) {
                console.log(error);
                return res.status(500).json({ error: true, msg: 'Failed to delete user.' });
            }
            return res.status(200).send({ error: false, msg: 'Pacient deleted successfully.' });
        });
    } catch (error) {
        console.log(error)
    }

});


router.post('/getutilizator/:id', checkTokenExistence, (req, res, next) => {
    try {
        const theToken = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(theToken, process.env.JWT_SECRET);
        db.query('SELECT * FROM users where id=?', req.params.id, function (error, results, fields) {
            if (error) throw error;
            return res.send({ error: false, data: results[0], msg: 'Fetch Successfully.' });
        });
    } catch (error) {
        console.log(error)
    }

});

router.post('/verifytoken', (req, res) => {
    try {
        if (
            !req.headers.authorization ||
            !req.headers.authorization.startsWith('Bearer') ||
            !req.headers.authorization.split(' ')[1]
        ) {
            return res.status(422).json({
                message: "Please provide the token",
            });
        }
        const token = req.headers.authorization.split(' ')[1];
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                if (err instanceof jwt.TokenExpiredError) {
                    return res.status(422).json({
                        message: "Token has expired, please login again!",
                    });
                } else {
                    return res.status(422).json({
                        message: "The token is not working",
                    });
                }
            }

            if (decoded && decoded.iss === 'http://smartcare.com') {
                return res.send({ error: false, data: decoded, message: 'TOKEN Valid.' });
            } else {
                return res.status(422).json({
                    message: "Please provide an original token",
                });
            }
        });
    } catch (error) {
        console.log("ERROR", error.name);
        res.status(500).json({ message: 'Internal server error' });
    }
});


module.exports = router;