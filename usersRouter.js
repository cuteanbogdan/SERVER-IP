const express = require("express");
const router = express.Router();
const db = require("./db.js");
const { signupValidation, loginValidation } = require("./validation.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");

const roles = {
    Administrator: "Administrator",
    Pacient: "Pacient",
    Doctor: "Doctor",
    Ingrijitor: "Ingrijitor",
    Supraveghetor: "Supraveghetor",
};

const checkTokenExistence = (req, res, next) => {
    try {
        if (
            !req.headers.authorization ||
            !req.headers.authorization.startsWith("Bearer") ||
            !req.headers.authorization.split(" ")[1]
        ) {
            return res.status(422).json({
                message: "Please provide the token",
            });
        }
        const token = req.headers.authorization.split(" ")[1];
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

            if (decoded && decoded.iss === "http://smartcare.com") {
                next();
            } else {
                return res.status(422).json({
                    message: "Please provide an original token",
                });
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

router.post(
    "/register",
    signupValidation,
    checkTokenExistence,
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const errorMessages = errors.array().map((error) => error.msg);
            return res.status(400).json({ errors: errorMessages });
        }
        try {
            db.query(
                `(
            SELECT email FROM Administratori WHERE LOWER(email) = LOWER(${db.escape(
                    req.body.email
                )})
        ) UNION (
            SELECT email FROM Pacienti WHERE LOWER(email) = LOWER(${db.escape(
                    req.body.email
                )})
        ) UNION (
            SELECT email FROM Doctori WHERE LOWER(email) = LOWER(${db.escape(
                    req.body.email
                )})
        ) UNION (
            SELECT email FROM Ingrijitori WHERE LOWER(email) = LOWER(${db.escape(
                    req.body.email
                )})
        ) UNION (
            SELECT email FROM Supraveghetori WHERE LOWER(email) = LOWER(${db.escape(
                    req.body.email
                )})
        );`,
                (err, result) => {
                    if (result.length) {
                        return res.status(409).send({
                            msg: "This user email is already in use!",
                        });
                    } else {
                        switch (req.body.rol) {
                            case "Administrator":
                                db.query(
                                    `SELECT * FROM Administratori WHERE LOWER(email) = LOWER(${db.escape(
                                        req.body.email
                                    )});`,
                                    (err, result) => {
                                        if (result.length) {
                                            return res.status(409).send({
                                                msg: "This administrator is already in use!",
                                            });
                                        } else {
                                            // username is available
                                            bcrypt.hash(req.body.password, 10, (err, hash) => {
                                                if (err) {
                                                    return res.status(500).send({
                                                        msg: err,
                                                    });
                                                } else {
                                                    // has hashed pw => add to database
                                                    db.query(
                                                        `INSERT INTO Administratori (rol, nume, prenume, email, parola) VALUES (${db.escape(
                                                            roles[req.body.rol]
                                                        )}, ${db.escape(req.body.nume)}, ${db.escape(
                                                            req.body.prenume
                                                        )},
                                                ${db.escape(
                                                            req.body.email
                                                        )}, ${db.escape(hash)})`,
                                                        (err, result) => {
                                                            if (err) {
                                                                return res.status(400).send({
                                                                    msg: err,
                                                                });
                                                            }
                                                            return res.status(201).send({
                                                                msg: "The user has been registered with us!",
                                                            });
                                                        }
                                                    );
                                                }
                                            });
                                        }
                                    }
                                );
                                break;
                            case "Doctor":
                                db.query(
                                    `SELECT * FROM Doctori WHERE LOWER(email) = LOWER(${db.escape(
                                        req.body.email
                                    )});`,
                                    (err, result) => {
                                        if (result.length) {
                                            return res.status(409).send({
                                                msg: "This doctor is already in use!",
                                            });
                                        } else {
                                            // username is available
                                            bcrypt.hash(req.body.password, 10, (err, hash) => {
                                                if (err) {
                                                    return res.status(500).send({
                                                        msg: err,
                                                    });
                                                } else {
                                                    // has hashed pw => add to database
                                                    db.query(
                                                        `INSERT INTO Doctori (rol, nume, prenume, email ,parola) VALUES (${db.escape(
                                                            roles[req.body.rol]
                                                        )}, ${db.escape(req.body.nume)}, ${db.escape(
                                                            req.body.prenume
                                                        )},
                                                ${db.escape(
                                                            req.body.email
                                                        )}, ${db.escape(hash)})`,
                                                        (err, result) => {
                                                            if (err) {
                                                                return res.status(400).send({
                                                                    msg: err,
                                                                });
                                                            }
                                                            return res.status(201).send({
                                                                msg: "The doctor has been registered with us!",
                                                            });
                                                        }
                                                    );
                                                }
                                            });
                                        }
                                    }
                                );
                                break;
                            case "Pacient":
                                db.query(
                                    `SELECT * FROM Pacienti WHERE LOWER(email) = LOWER(${db.escape(
                                        req.body.email
                                    )});`,
                                    (err, result) => {
                                        if (result.length) {
                                            return res.status(409).send({
                                                msg: "This patient is already in use!",
                                            });
                                        } else {
                                            // email is available
                                            bcrypt.hash(req.body.password, 10, (err, hash) => {
                                                if (err) {
                                                    return res.status(500).send({
                                                        msg: err,
                                                    });
                                                } else {
                                                    // has hashed pw => add to database
                                                    // Insert a row into date_medicale first
                                                    db.query(
                                                        `INSERT INTO Date_Medicale (antcedente, istoric_consultatii, urmatoarea_consultatie, alergii, afectiuni_cronice, diagnostic_curent, diagnostic_istoric, medicatie_curenta, medicatie_istoric) 
                                                        VALUES (NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)`,
                                                        (err, resultDateMedicale) => {
                                                            if (err) {
                                                                return res.status(400).send({
                                                                    msg: err,
                                                                });
                                                            }

                                                            db.query(
                                                                `INSERT INTO date_colectate (TA, puls, temp_corp, greutate, glicemie, grad_iluminare, temp_amb, saturatie_gaz, umiditate, proximitate) 
                                                        VALUES (-1, -1, -1, -1, -1, -1, -1, -1, -1, -1)`,
                                                                (err, resultDateColectate) => {
                                                                    if (err) {
                                                                        return res.status(400).send({
                                                                            msg: err,
                                                                        });
                                                                    }

                                                                    db.query(
                                                                        `INSERT INTO parametri_normali ( TA_min, TA_max, puls_min, puls_max, temp_corp_min, temp_corp_max, greutate_min, greutate_max, glicemie_min, glicemie_max, temp_amb_min, temp_amb_max, saturatie_gaz_min, saturatie_gaz_max, umiditate_min, umiditate_max, proximitate_min, proximitate_max) 
                                                                VALUES (-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,-1, -1, -1, -1, -1, -1, -1, -1)`,
                                                                        (err, resultDateParametri) => {
                                                                            if (err) {
                                                                                return res.status(400).send({
                                                                                    msg: err,
                                                                                });
                                                                            }
                                                                            // Now that we have an id_medical,id_colectie, id_parametru, id_recomandare create a Pacienti record
                                                                            db.query(
                                                                                `INSERT INTO Pacienti (id_parametru, id_colectie, id_medical, rol, cnp, nume, prenume, adresa, nr_tel, nr_tel_pers_contact, email, profesie, loc_munca, parola, varsta) VALUES (${resultDateParametri.insertId},${resultDateColectate.insertId},${resultDateMedicale.insertId}, ${db.escape(
                                                                                    roles[req.body.rol]
                                                                                )}, ${db.escape(req.body.cnp)}, ${db.escape(
                                                                                    req.body.nume
                                                                                )}, ${db.escape(req.body.prenume)}, ${db.escape(
                                                                                    req.body.adresa
                                                                                )}, ${db.escape(req.body.nr_tel)}, ${db.escape(
                                                                                    req.body.nr_tel_pers_contact
                                                                                )}, ${db.escape(
                                                                                    req.body.email
                                                                                )}, ${db.escape(
                                                                                    req.body.profesie
                                                                                )}, ${db.escape(req.body.loc_munca)}, ${db.escape(
                                                                                    hash
                                                                                )}, ${db.escape(req.body.varsta)})`,
                                                                                (err, result) => {
                                                                                    if (err) {
                                                                                        return res.status(400).send({
                                                                                            msg: err,
                                                                                        });
                                                                                    }

                                                                                    if (req.body.supraveghetorId) {
                                                                                        // Update Supraveghetori table.
                                                                                        db.query(
                                                                                            `UPDATE Supraveghetori SET id_pacient = ${result.insertId
                                                                                            } WHERE id_supraveghetor = ${db.escape(
                                                                                                req.body.supraveghetorId
                                                                                            )}`,
                                                                                            (err, result) => {
                                                                                                if (err) {
                                                                                                    return res.status(400).send({
                                                                                                        msg: err,
                                                                                                    });
                                                                                                }
                                                                                            }
                                                                                        );
                                                                                    }

                                                                                    if (req.body.ingrijitorId) {
                                                                                        // Update Ingrijitori table.
                                                                                        db.query(
                                                                                            `UPDATE Ingrijitori SET id_pacient = ${result.insertId
                                                                                            } WHERE id_ingrijitor = ${db.escape(
                                                                                                req.body.ingrijitorId
                                                                                            )}`,
                                                                                            (err, result) => {
                                                                                                if (err) {
                                                                                                    return res.status(400).send({
                                                                                                        msg: err,
                                                                                                    });
                                                                                                }
                                                                                                return res.status(201).send({
                                                                                                    msg: "The patient has been registered with us and assigned to the caregiver and supervisor!",
                                                                                                });
                                                                                            }
                                                                                        );
                                                                                    }

                                                                                    if (!req.body.supraveghetorId && !req.body.ingrijitorId) {
                                                                                        return res.status(201).send({
                                                                                            msg: "The patient has been registered with us, but has not been assigned to a caregiver or supervisor"
                                                                                        });
                                                                                    }
                                                                                }
                                                                            );
                                                                        }
                                                                    )
                                                                }
                                                            );
                                                        })
                                                }
                                            });
                                        }
                                    }
                                );
                                break;
                            case "Ingrijitor":
                                db.query(
                                    `SELECT * FROM Ingrijitori WHERE LOWER(email) = LOWER(${db.escape(
                                        req.body.email
                                    )});`,
                                    (err, result) => {
                                        if (result.length) {
                                            return res.status(409).send({
                                                msg: "This ingrijitor is already in use!",
                                            });
                                        } else {
                                            // username is available
                                            bcrypt.hash(req.body.password, 10, (err, hash) => {
                                                if (err) {
                                                    return res.status(500).send({
                                                        msg: err,
                                                    });
                                                } else {
                                                    // has hashed pw => add to database
                                                    db.query(
                                                        `INSERT INTO Ingrijitori (rol, nume, prenume, email ,parola) VALUES (${db.escape(
                                                            roles[req.body.rol]
                                                        )}, ${db.escape(req.body.nume)}, ${db.escape(
                                                            req.body.prenume
                                                        )},
                                                ${db.escape(
                                                            req.body.email
                                                        )}, ${db.escape(hash)})`,
                                                        (err, result) => {
                                                            if (err) {
                                                                return res.status(400).send({
                                                                    msg: err,
                                                                });
                                                            }
                                                            return res.status(201).send({
                                                                msg: "The ingrijitor has been registered with us!",
                                                            });
                                                        }
                                                    );
                                                }
                                            });
                                        }
                                    }
                                );
                                break;
                            case "Supraveghetor":
                                db.query(
                                    `SELECT * FROM Supraveghetori WHERE LOWER(email) = LOWER(${db.escape(
                                        req.body.email
                                    )});`,
                                    (err, result) => {
                                        if (result.length) {
                                            return res.status(409).send({
                                                msg: "This supraveghetor is already in use!",
                                            });
                                        } else {
                                            // username is available
                                            bcrypt.hash(req.body.password, 10, (err, hash) => {
                                                if (err) {
                                                    return res.status(500).send({
                                                        msg: err,
                                                    });
                                                } else {
                                                    // has hashed pw => add to database
                                                    db.query(
                                                        `INSERT INTO Supraveghetori (rol, nume, prenume, email ,parola) VALUES (${db.escape(
                                                            roles[req.body.rol]
                                                        )}, ${db.escape(req.body.nume)}, ${db.escape(
                                                            req.body.prenume
                                                        )},
                                                ${db.escape(
                                                            req.body.email
                                                        )}, ${db.escape(hash)})`,
                                                        (err, result) => {
                                                            if (err) {
                                                                return res.status(400).send({
                                                                    msg: err,
                                                                });
                                                            }
                                                            return res.status(201).send({
                                                                msg: "The supraveghetor has been registered with us!",
                                                            });
                                                        }
                                                    );
                                                }
                                            });
                                        }
                                    }
                                );
                                break;
                            default:
                                console.log("No role: ", req.body.rol);
                                break;
                        }
                    }
                }
            );
        } catch (err) {
            console.log(err);
        }
    }
);

router.post("/login", loginValidation, (req, res, next) => {
    let payload;
    try {
        db.query(
            `
    SELECT id_doctor, NULL as id_pacient, NULL as id_ingrijitor, NULL as id_supraveghetor, NULL as id_administrator, email, parola, rol, nume FROM Doctori WHERE email = ${db.escape(
                req.body.email
            )}
    UNION ALL
    SELECT NULL as id_doctor, id_pacient, NULL as id_ingrijitor, NULL as id_supraveghetor, NULL as id_administrator, email, parola, rol, nume FROM Pacienti WHERE email = ${db.escape(
                req.body.email
            )}
    UNION ALL
    SELECT NULL as id_doctor, NULL as id_pacient, id_ingrijitor, NULL as id_supraveghetor, NULL as id_administrator, email, parola, rol, nume FROM Ingrijitori WHERE email = ${db.escape(
                req.body.email
            )}
    UNION ALL
    SELECT NULL as id_doctor, NULL as id_pacient, NULL as id_ingrijitor, id_supraveghetor, NULL as id_administrator, email, parola, rol, nume FROM Supraveghetori WHERE email = ${db.escape(
                req.body.email
            )}
    UNION ALL
    SELECT NULL as id_doctor, NULL as id_pacient, NULL as id_ingrijitor, NULL as id_supraveghetor, id_administrator, email, parola, rol, nume FROM Administratori WHERE email = ${db.escape(
                req.body.email
            )}
`,
            (err, result) => {
                // user does not exists
                if (err) {
                    return res.status(400).send({
                        msg: err,
                    });
                }
                if (!result.length) {
                    return res.status(401).send({
                        msg: "Email or password is incorrect!",
                    });
                }
                // check password
                bcrypt.compare(
                    req.body.password,
                    result[0]["parola"],
                    (bErr, bResult) => {
                        // wrong password
                        if (bErr) {
                            console.log(bErr);
                            return res.status(401).send({
                                msg: "Email or password is incorrect!",
                            });
                        }
                        if (bResult) {
                            const modifiedRole =
                                result[0].rol.charAt(0).toLowerCase() + result[0].rol.slice(1);
                            const idKey = `id_${modifiedRole}`;
                            //iau ID-ul
                            const getIdValue = (result) => {
                                if (result.id_doctor !== null) return result.id_doctor;
                                if (result.id_pacient !== null) return result.id_pacient;
                                if (result.id_ingrijitor !== null) return result.id_ingrijitor;
                                if (result.id_supraveghetor !== null)
                                    return result.id_supraveghetor;
                                if (result.id_administrator !== null)
                                    return result.id_administrator;
                            };
                            const idValue = getIdValue(result[0]);
                            //payload starndard pentru toti utilizatorii
                            let initialPayload = {
                                [idKey]: `${idValue}`,
                                email: result[0].email,
                                rol: result[0].rol,
                            };
                            switch (result[0].rol) {
                                //payload personificat pt fiecare
                                case "Administrator":
                                    payload = { ...initialPayload, nume: result[0].nume };
                                    break;
                                case "Doctor":
                                    payload = { ...initialPayload, nume: result[0].nume };
                                    break;
                                case "Pacient":
                                    payload = { ...initialPayload, nume: result[0].nume };
                                    break;
                                case "Ingrijitor":
                                    payload = { ...initialPayload, nume: result[0].nume };
                                    break;
                                case "Supraveghetor":
                                    payload = { ...initialPayload, nume: result[0].nume };
                                    break;
                            }
                            const token = jwt.sign(payload, process.env.JWT_SECRET, {
                                issuer: "http://smartcare.com",
                                expiresIn: "24h",
                            });
                            return res.status(200).send({
                                msg: "Logged in!",
                                token,
                            });
                        }
                        return res.status(401).send({
                            msg: "Email or password is incorrect!",
                        });
                    }
                );
            }
        );
    } catch (error) {
        console.log(error);
    }
});

router.post("/get-ingrijitor", checkTokenExistence, (req, res, next) => {
    try {
        const theToken = req.headers.authorization.split(" ")[1];
        const decoded = jwt.verify(theToken, process.env.JWT_SECRET);
        db.query(
            "SELECT email, id_ingrijitor, id_pacient, nume, prenume FROM Ingrijitori where id_ingrijitor = ?",
            [decoded.id_ingrijitor],
            function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .json({ error: true, msg: "Failed to fetch ingrijitor." });
                }
                return res.send({
                    error: false,
                    data: results[0],
                    msg: "Fetch Successfully.",
                });
            }
        );

    } catch (error) {
        console.log(error);
    }
});

router.post("/get-supraveghetor", checkTokenExistence, (req, res, next) => {
    try {
        const theToken = req.headers.authorization.split(" ")[1];
        const decoded = jwt.verify(theToken, process.env.JWT_SECRET);
        db.query(
            "SELECT email, id_supraveghetor, id_pacient, nume, prenume FROM Supraveghetori where id_supraveghetor = ?",
            [decoded.id_supraveghetor],
            function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .json({ error: true, msg: "Failed to fetch supraveghetor." });
                }
                return res.send({
                    error: false,
                    data: results[0],
                    msg: "Fetch Successfully.",
                });
            }
        );

    } catch (error) {
        console.log(error);
    }
});

router.post("/getallusers", checkTokenExistence, (req, res, next) => {
    try {
        db.query(
            `
    SELECT id_doctor, NULL as id_pacient, NULL as id_ingrijitor, NULL as id_supraveghetor, NULL as id_administrator, email, parola, rol, nume, prenume FROM Doctori
    UNION ALL
    SELECT NULL as id_doctor, id_pacient, NULL as id_ingrijitor, NULL as id_supraveghetor, NULL as id_administrator, email, parola, rol, nume, prenume FROM Pacienti 
    UNION ALL
    SELECT NULL as id_doctor, NULL as id_pacient, id_ingrijitor, NULL as id_supraveghetor, NULL as id_administrator, email, parola, rol, nume, prenume FROM Ingrijitori 
    UNION ALL
    SELECT NULL as id_doctor, NULL as id_pacient, NULL as id_ingrijitor, id_supraveghetor, NULL as id_administrator, email, parola, rol, nume, prenume FROM Supraveghetori 
    UNION ALL
    SELECT NULL as id_doctor, NULL as id_pacient, NULL as id_ingrijitor, NULL as id_supraveghetor, id_administrator, email, parola, rol, nume, prenume FROM Administratori 
`,
            function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .json({ error: true, msg: "Failed to fetch users." });
                }
                return res
                    .status(200)
                    .send({ error: false, data: results, msg: "Fetch Successfully." });
            }
        );
    } catch (error) {
        console.log(error);
    }
});

router.post("/getallpacients", checkTokenExistence, (req, res, next) => {
    try {
        db.query(
            "SELECT * FROM Pacienti WHERE rol = ?",
            ["Pacient"],
            function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .send({ error: true, msg: "Failed to retrieve data." });
                }
                return res
                    .status(200)
                    .send({ error: false, data: results, msg: "Fetch Successfully." });
            }
        );
    } catch (error) {
        console.log(error);
    }
});

router.post("/getallsupraveghetori", checkTokenExistence, (req, res, next) => {
    try {
        db.query(
            "SELECT * FROM Supraveghetori WHERE rol = ? AND id_pacient IS NULL",
            ["Supraveghetor"],
            function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .send({ error: true, msg: "Failed to retrieve data." });
                }
                return res
                    .status(200)
                    .send({ error: false, data: results, msg: "Fetch Successfully." });
            }
        );
    } catch (error) {
        console.log(error);
    }
});

router.post("/getallingrijitori", checkTokenExistence, (req, res, next) => {
    try {
        db.query(
            "SELECT * FROM Ingrijitori WHERE rol = ? AND id_pacient IS NULL",
            ["Ingrijitor"],
            function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .send({ error: true, msg: "Failed to retrieve data." });
                }
                return res
                    .status(200)
                    .send({ error: false, data: results, msg: "Fetch Successfully." });
            }
        );
    } catch (error) {
        console.log(error);
    }
});

router.post("/delete-user/:email", checkTokenExistence, (req, res, next) => {
    try {
        const userEmail = req.params.email;
        const tables = [
            "Administratori",
            "Pacienti",
            "Doctori",
            "Ingrijitori",
            "Supraveghetori",
        ];

        const deleteFromTable = (index) => {
            if (index >= tables.length) {
                return res
                    .status(200)
                    .send({ error: false, msg: "User deleted successfully." });
            }
            db.query(
                `DELETE FROM ${tables[index]} WHERE LOWER(email) = LOWER(?)`,
                [userEmail],
                (error, results, fields) => {
                    if (error) {
                        console.log(error);
                        return res
                            .status(500)
                            .json({ error: true, msg: "Failed to delete user." });
                    }

                    deleteFromTable(index + 1);
                }
            );
        };
        deleteFromTable(0);
    } catch (error) {
        console.log(error);
    }
});

router.post("/delete-pacient/:id", checkTokenExistence, (req, res, next) => {
    const userId = req.params.id;

    // Set the id_pacient field to NULL in the Ingrijitori table
    db.query(
        "UPDATE Ingrijitori SET id_pacient = NULL WHERE id_pacient = ?",
        [userId],
        function (error, results, fields) {
            if (error) {
                console.log(error);
                return res
                    .status(500)
                    .json({ error: true, msg: "Failed to update Ingrijitori entries." });
            }

            // Set the id_pacient field to NULL in the Supraveghetori table
            db.query(
                "UPDATE Supraveghetori SET id_pacient = NULL WHERE id_pacient = ?",
                [userId],
                function (error, results, fields) {
                    if (error) {
                        console.log(error);
                        return res
                            .status(500)
                            .json({ error: true, msg: "Failed to update Supraveghetori entries." });
                    }

                    // Delete the Pacienti
                    db.query(
                        "DELETE FROM Pacienti WHERE id_pacient = ?",
                        [userId],
                        function (error, results, fields) {
                            if (error) {
                                console.log(error);
                                return res
                                    .status(500)
                                    .json({ error: true, msg: "Failed to delete user." });
                            }
                            return res
                                .status(200)
                                .send({ error: false, msg: "Pacient deleted successfully." });
                        }
                    );
                }
            );
        }
    );
});

router.post("/clear-alarma/:id", checkTokenExistence, async (req, res, next) => {
    try {
        const alarmaId = req.params.id;
        // Step 1: Set the id_alarma field to NULL in the Pacienti table
        db.query(
            "UPDATE Pacienti SET id_alarma = NULL WHERE id_alarma = ?",
            [alarmaId],
            function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .json({ error: true, msg: "Failed to update Pacienti table" });
                }
                // Step 2: Delete the alarm
                db.query(
                    "DELETE FROM Alarme WHERE id_alarma = ?",
                    [alarmaId],
                    function (error, results, fields) {
                        if (error) {
                            console.log(error);
                            return res
                                .status(500)
                                .json({ error: true, msg: "Failed to clear alarma" });
                        }
                        if (results.affectedRows === 0) {
                            return res
                                .status(404)
                                .json({ error: true, msg: "Alarma not found" });
                        }
                        return res
                            .status(200)
                            .json({ error: false, msg: "Alarma tratata cu success" });
                    }
                );
            }
        );
    } catch (error) {
        console.log(error);
        return res
            .status(500)
            .json({ error: true, msg: "An error occurred on the server" });
    }
});


router.post(
    "/get-pacient-details/:id",
    checkTokenExistence,
    (req, res, next) => {
        try {
            const userId = req.params.id;
            db.query(
                "SELECT rol, cnp, nume, prenume, adresa, nr_tel, nr_tel_pers_contact, email, profesie, loc_munca, varsta, id_medical, id_colectie, id_parametru, id_recomandare, id_alarma FROM Pacienti WHERE id_pacient = ?",
                [userId],
                function (error, results, fields) {
                    if (error) {
                        console.log(error);
                        return res
                            .status(500)
                            .json({ error: true, msg: "Failed to fetch patient details." });
                    }
                    if (!results.length) {
                        return res
                            .status(404)
                            .json({ error: true, msg: "Patient not found." });
                    }
                    return res.status(200).send({
                        error: false,
                        msg: "Patient details fetched successfully.",
                        data: results[0],
                    });
                }
            );
        } catch (error) {
            console.log(error);
        }
    }
);

router.post(
    "/get-date-medicale-patient/:id",
    checkTokenExistence,
    (req, res, next) => {
        try {
            const userId = req.params.id;
            db.query(
                "SELECT antcedente, istoric_consultatii, urmatoarea_consultatie, alergii, afectiuni_cronice, diagnostic_curent, diagnostic_istoric, medicatie_curenta, medicatie_istoric FROM Date_Medicale WHERE id_medical = ?",
                [userId],
                function (error, results, fields) {
                    if (error) {
                        console.log(error);
                        return res
                            .status(500)
                            .json({ error: true, msg: "Failed to fetch medical data." });
                    }
                    if (!results.length) {
                        return res
                            .status(404)
                            .json({ error: true, msg: "Medical data not found." });
                    }
                    return res.status(200).send({
                        error: false,
                        msg: "Medical data fetched successfully.",
                        data: results[0],
                    });
                }
            );
        } catch (error) {
            console.log(error);
        }
    }
);

router.post(
    "/get-date-colectate-patient/:id",
    checkTokenExistence,
    (req, res, next) => {
        try {
            const userId = req.params.id;
            db.query(
                "SELECT TA, puls, temp_corp, greutate, glicemie, grad_iluminare, temp_amb, saturatie_gaz, umiditate, proximitate FROM date_colectate WHERE id_colectie = ?",
                [userId],
                function (error, results, fields) {
                    if (error) {
                        console.log(error);
                        return res
                            .status(500)
                            .json({ error: true, msg: "Failed to fetch collected data." });
                    }
                    if (!results.length) {
                        return res
                            .status(404)
                            .json({ error: true, msg: "Collected data not found." });
                    }
                    return res.status(200).send({
                        error: false,
                        msg: "Collected data fetched successfully.",
                        data: results[0],
                    });
                }
            );
        } catch (error) {
            console.log(error);
        }
    }
);

router.get(
    "/get-alarm-details/:id",
    checkTokenExistence,
    (req, res, next) => {
        try {
            const alarmId = req.params.id;

            db.query(
                "SELECT * FROM Alarme WHERE id_alarma = ?",
                [alarmId],
                function (error, results, fields) {
                    if (error) {
                        console.log(error);
                        return res
                            .status(500)
                            .json({ error: true, msg: "Failed to fetch alarm details." });
                    }
                    if (!results.length) {
                        return res
                            .status(404)
                            .json({ error: true, msg: "Alarm not found." });
                    }
                    return res.status(200).send({
                        error: false,
                        msg: "Alarm details fetched successfully.",
                        data: results[0],
                    });
                }
            );
        } catch (error) {
            console.log(error);
            return res
                .status(500)
                .json({ error: true, msg: "An error occurred while fetching alarm details." });
        }
    }
);

router.get(
    "/get-recomandari-details/:id",
    checkTokenExistence,
    (req, res, next) => {
        try {
            const recomandareId = req.params.id;

            db.query(
                "SELECT * FROM recomandari WHERE id_recomandare = ?",
                [recomandareId],
                function (error, results, fields) {
                    if (error) {
                        console.log(error);
                        return res
                            .status(500)
                            .json({ error: true, msg: "Failed to fetch recomandari details." });
                    }
                    if (!results.length) {
                        return res
                            .status(404)
                            .json({ error: true, msg: "Recomandare not found." });
                    }

                    const dateInLocalTime = new Date(results[0].timp).toLocaleString("ro-RO", { timeZone: "Europe/Bucharest" });
                    results[0].timp = dateInLocalTime;

                    return res.status(200).send({
                        error: false,
                        msg: "Recomandari details fetched successfully.",
                        data: results[0],
                    });
                }
            );
        } catch (error) {
            console.log(error);
            return res
                .status(500)
                .json({ error: true, msg: "An error occurred while fetching recomandari details." });
        }
    }
);

router.post(
    "/get-parametri/:id",
    checkTokenExistence,
    (req, res, next) => {
        try {
            const userId = req.params.id;
            db.query(
                "SELECT TA_min, TA_max, puls_min, puls_max, temp_corp_min, temp_corp_max, greutate_min, greutate_max, glicemie_min, glicemie_max, temp_amb_min, temp_amb_max, saturatie_gaz_min, saturatie_gaz_max, umiditate_min, umiditate_max, proximitate_min, proximitate_max FROM parametri_normali WHERE id_parametru = ?",
                [userId],
                function (error, results, fields) {
                    if (error) {
                        console.log(error);
                        return res
                            .status(500)
                            .json({ error: true, msg: "Failed to fetch parametri data." });
                    }
                    if (!results.length) {
                        return res
                            .status(404)
                            .json({ error: true, msg: "Parametri data not found." });
                    }
                    return res.status(200).send({
                        error: false,
                        msg: "Parametri data fetched successfully.",
                        data: results[0],
                    });
                }
            );
        } catch (error) {
            console.log(error);
        }
    }
);

router.get("/get-date-istorice", checkTokenExistence, (req, res, next) => {
    try {
        db.query(
            "SELECT * FROM istoric_date",
            [],
            function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .json({ error: true, msg: "Failed to fetch istoric date data." });
                }
                if (!results.length) {
                    return res
                        .status(404)
                        .json({ error: true, msg: "Istoric date data not found." });
                }
                return res.status(200).send({
                    error: false,
                    msg: "Istoric date data fetched successfully.",
                    data: results,
                });
            }
        );
    } catch (error) {
        console.log(error);
    }
});

router.put(
    "/update-pacient-details/:id",
    checkTokenExistence,
    (req, res, next) => {
        try {
            const userId = req.params.id;
            const updatedData = req.body;

            let updateQuery = "UPDATE Pacienti SET ";
            let updateParams = [];

            // Loop through each property in the updatedData object and add it to the query
            for (let property in updatedData) {
                updateQuery += `${property} = ?, `;
                updateParams.push(updatedData[property]);
            }

            // Remove the last comma and space from the query
            updateQuery = updateQuery.slice(0, -2);

            updateQuery += " WHERE id_pacient = ?";
            updateParams.push(userId);

            db.query(updateQuery, updateParams, function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .json({ error: true, msg: "Failed to update patient details." });
                }
                if (results.affectedRows === 0) {
                    return res
                        .status(404)
                        .json({ error: true, msg: "Patient not found." });
                }
                return res.status(200).send({
                    error: false,
                    msg: "Patient details updated successfully.",
                });
            });
        } catch (error) {
            console.log(error);
        }
    }
);

router.put(
    "/update-date-medicale/:id",
    checkTokenExistence,
    (req, res, next) => {
        try {
            const userId = req.params.id;
            const updatedData = req.body;

            let updateQuery = "UPDATE Date_Medicale SET ";
            let updateParams = [];

            // Loop through each property in the updatedData object and add it to the query
            for (let property in updatedData) {
                updateQuery += `${property} = ?, `;
                updateParams.push(updatedData[property]);
            }

            // Remove the last comma and space from the query
            updateQuery = updateQuery.slice(0, -2);

            updateQuery += " WHERE id_medical = ?";
            updateParams.push(userId);

            db.query(updateQuery, updateParams, function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .json({ error: true, msg: "Failed to update medical details." });
                }
                if (results.affectedRows === 0) {
                    return res
                        .status(404)
                        .json({ error: true, msg: "No medical record found for this patient." });
                }
                return res.status(200).send({
                    error: false,
                    msg: "Medical details updated successfully.",
                });
            });
        } catch (error) {
            console.log(error);
        }
    }
);

router.put("/update-date-colectate/:id", checkTokenExistence, (req, res, next) => {
    try {
        const id_colectie = req.params.id;
        const updatedData = req.body;

        let updateQuery = "UPDATE Date_Colectate SET ";
        let updateParams = [];

        // Loop through each property in the updatedData object and add it to the query
        for (let property in updatedData) {
            updateQuery += `${property} = ?, `;
            updateParams.push(updatedData[property]);
        }

        // Remove the last comma and space from the query
        updateQuery = updateQuery.slice(0, -2);

        updateQuery += " WHERE id_colectie = ?";
        updateParams.push(id_colectie);

        db.query(updateQuery, updateParams, function (error, results, fields) {
            if (error) {
                console.log(error);
                return res
                    .status(500)
                    .json({ error: true, msg: "Failed to update collected date details." });
            }

            if (results.affectedRows === 0) {
                return res
                    .status(404)
                    .json({ error: true, msg: "No collected date record found for this user." });
            }

            // create new row in istoric_date table
            const istoricData = {
                tensiune: updatedData.TA,
                temperatura_corp: updatedData.temp_corp,
                greutate: updatedData.greutate,
                glicemie: updatedData.glicemie,
            };
            let istoricQuery = "INSERT INTO istoric_date SET ?";
            db.query(istoricQuery, istoricData, function (err, results) {
                if (err) {
                    console.log(err);
                    return res
                        .status(500)
                        .json({ error: true, msg: "Failed to insert data into istoric_date." });
                }
                return res.status(200).send({
                    error: false,
                    msg: "Collected date details updated successfully and data added to istoric_date.",
                });
            });
        });
    } catch (error) {
        console.log(error);
    }
});

router.put(
    "/update-parametri/:id",
    checkTokenExistence,
    (req, res, next) => {
        try {
            const userId = req.params.id;
            const updatedData = req.body;

            let updateQuery = "UPDATE parametri_normali SET ";
            let updateParams = [];

            // Loop through each property in the updatedData object and add it to the query
            for (let property in updatedData) {
                updateQuery += `${property} = ?, `;
                updateParams.push(updatedData[property]);
            }

            // Remove the last comma and space from the query
            updateQuery = updateQuery.slice(0, -2);

            updateQuery += " WHERE id_parametru = ?";
            updateParams.push(userId);

            db.query(updateQuery, updateParams, function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .json({ error: true, msg: "Failed to update parametri details." });
                }
                if (results.affectedRows === 0) {
                    return res
                        .status(404)
                        .json({ error: true, msg: "No medical record found for this patient." });
                }
                return res.status(200).send({
                    error: false,
                    msg: "Parametri details updated successfully.",
                });
            });
        } catch (error) {
            console.log(error);
        }
    }
);

router.post("/recomandare-doctor/:id", checkTokenExistence, (req, res, next) => {
    try {
        const id_pacient = req.params.id;
        const recomandare = req.body.recomandareDoctor;
        const timp = req.body.timpDoctor;
        const detalii = req.body.detaliiDoctor;

        const insertQuery = "INSERT INTO recomandari (recomandare, timp, detalii) VALUES (?, ?, ?)";
        const insertParams = [recomandare, timp, detalii];

        db.query(insertQuery, insertParams, function (error, results, fields) {
            if (error) {
                console.log(error);
                return res
                    .status(500)
                    .json({ error: true, msg: "Failed to insert recommendation." });
            }

            // Get the ID of the newly created recommendation
            const id_recomandare = results.insertId;

            // Now we will update the patient row with this new recommendation ID
            const updateQuery = "UPDATE Pacienti SET id_recomandare = ? WHERE id_pacient = ?";
            const updateParams = [id_recomandare, id_pacient];

            db.query(updateQuery, updateParams, function (error, results, fields) {
                if (error) {
                    console.log(error);
                    return res
                        .status(500)
                        .json({ error: true, msg: "Failed to update patient with recommendation." });
                }
                return res.status(200).send({
                    error: false,
                    msg: "Recomandare adaugata cu success",
                });
            });
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: true, msg: "An error occurred." });
    }
});

router.post("/verifytoken", (req, res) => {
    try {
        if (
            !req.headers.authorization ||
            !req.headers.authorization.startsWith("Bearer") ||
            !req.headers.authorization.split(" ")[1]
        ) {
            return res.status(422).json({
                message: "Please provide the token",
            });
        }
        const token = req.headers.authorization.split(" ")[1];
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

            if (decoded && decoded.iss === "http://smartcare.com") {
                return res.send({
                    error: false,
                    data: decoded,
                    message: "TOKEN Valid.",
                });
            } else {
                return res.status(422).json({
                    message: "Please provide an original token",
                });
            }
        });
    } catch (error) {
        console.log("ERROR", error.name);
        res.status(500).json({ message: "Internal server error" });
    }
});

module.exports = router;
