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
                      // username is available
                      bcrypt.hash(req.body.password, 10, (err, hash) => {
                        if (err) {
                          return res.status(500).send({
                            msg: err,
                          });
                        } else {
                          // has hashed pw => add to database
                          db.query(
                            `INSERT INTO Pacienti (rol, cnp, nume, prenume, adresa, nr_tel, nr_tel_pers_contact, email, profesie, loc_munca, parola, varsta) VALUES (${db.escape(
                              roles[req.body.rol]
                            )}, ${db.escape(req.body.cnp)}, ${db.escape(
                              req.body.nume
                            )}, ${db.escape(req.body.prenume)}, ${db.escape(
                              req.body.adresa
                            )}, ${db.escape(req.body.nr_tel)}, ${db.escape(
                              req.body.nr_tel_pers_contact
                            )}, 
                                                    ${db.escape(
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
                              // Insertion to Pacienti table was successful. Now update Supraveghetori table.
                              db.query(
                                `UPDATE Supraveghetori SET id_pacient = ${
                                  result.insertId
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
                              // Insertion to Pacienti table was successful. Now update Ingrijitori table.
                              db.query(
                                `UPDATE Ingrijitori SET id_pacient = ${
                                  result.insertId
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
                          );
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
              console.log("RESULT[0]: ", result[0]);
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
                user: result[0],
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

router.post("/get-user", checkTokenExistence, (req, res, next) => {
  try {
    const theToken = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(theToken, process.env.JWT_SECRET);
    db.query(
      "SELECT * FROM users where id=?",
      decoded.id,
      function (error, results, fields) {
        if (error) {
          console.log(error);
          return res
            .status(500)
            .json({ error: true, msg: "Failed to fetch user." });
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
    SELECT id_doctor, NULL as id_pacient, NULL as id_ingrijitor, NULL as id_supraveghetor, NULL as id_administrator, email, parola, rol, nume FROM Doctori
    UNION ALL
    SELECT NULL as id_doctor, id_pacient, NULL as id_ingrijitor, NULL as id_supraveghetor, NULL as id_administrator, email, parola, rol, nume FROM Pacienti 
    UNION ALL
    SELECT NULL as id_doctor, NULL as id_pacient, id_ingrijitor, NULL as id_supraveghetor, NULL as id_administrator, email, parola, rol, nume FROM Ingrijitori 
    UNION ALL
    SELECT NULL as id_doctor, NULL as id_pacient, NULL as id_ingrijitor, id_supraveghetor, NULL as id_administrator, email, parola, rol, nume FROM Supraveghetori 
    UNION ALL
    SELECT NULL as id_doctor, NULL as id_pacient, NULL as id_ingrijitor, NULL as id_supraveghetor, id_administrator, email, parola, rol, nume FROM Administratori 
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

// router.put('/update-user-role/:id', checkTokenExistence, (req, res) => {
//     try {
//         const userId = req.params.id;
//         const { role } = req.body;
//         db.query('UPDATE users_database SET role = ? WHERE id = ?', [role, userId], (err, result) => {
//             if (err) {
//                 console.log(err);
//                 return res.status(500).json({ error: true, msg: 'Failed to update user role.' });
//             }
//             return res.status(200).json({ error: false, msg: 'User role updated successfully.' });
//         });
//     } catch (error) {
//         console.log(error)
//     }
// });

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
  try {
    const userId = req.params.id;
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
  } catch (error) {
    console.log(error);
  }
});

router.post(
  "/get-pacient-details/:id",
  checkTokenExistence,
  (req, res, next) => {
    try {
      const userId = req.params.id;
      db.query(
        "SELECT rol, cnp, nume, prenume, adresa, nr_tel, nr_tel_pers_contact, email, profesie, loc_munca, varsta FROM Pacienti WHERE id_pacient = ?",
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

router.post("/getutilizator/:id", checkTokenExistence, (req, res, next) => {
  try {
    const theToken = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(theToken, process.env.JWT_SECRET);
    db.query(
      "SELECT * FROM users where id=?",
      req.params.id,
      function (error, results, fields) {
        if (error) throw error;
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
