const express = require("express");
const router = express.Router();
const db = require("./db.js");
const bcrypt = require("bcrypt");
const { uuid } = require("uuidv4");
const nodemailer = require("nodemailer");

//send email
function sendEmail(email, token) {
  var email = email;
  var token = token;

  var mail = nodemailer.createTransport({
    service: "yahoo",
    auth: {
      user: process.env.EMAIL, // Your email id
      pass: process.env.PASSWORD_EMAIL, // Your password
    },
  });

  var mailOptions = {
    from: "cutybogdy@yahoo.com",
    to: email,
    subject: "Link-ul pentru resetarea parolei - SmartCare.com",
    html:
      '<p>Ati cerut resetarea parolei, pentru a merge mai departe va rugam accesati <a href="https://smartcareip.netlify.app/update-password?token=' +
      token +
      '">link</a> pentru a va putea reseta parola</p>',
  };

  mail.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(1);
    } else {
      console.log(0);
    }
  });
}
/* send reset password link in email */
router.post("/change-password-email", async function (req, res) {
  try {
    const email = req.body.email;

    db.query(
      `(
            SELECT email, 'Administratori' as table_name FROM Administratori WHERE LOWER(email) = LOWER(${db.escape(
        email
      )})
        ) UNION (
            SELECT email, 'Pacienti' as table_name FROM Pacienti WHERE LOWER(email) = LOWER(${db.escape(
        email
      )})
        ) UNION (
            SELECT email, 'Doctori' as table_name FROM Doctori WHERE LOWER(email) = LOWER(${db.escape(
        email
      )})
        ) UNION (
            SELECT email, 'Ingrijitori' as table_name FROM Ingrijitori WHERE LOWER(email) = LOWER(${db.escape(
        email
      )})
        ) UNION (
            SELECT email, 'Supraveghetori' as table_name FROM Supraveghetori WHERE LOWER(email) = LOWER(${db.escape(
        email
      )})
        );`,
      async function (err, result) {
        if (err) {
          console.error(err);
          return res.status(500).json({
            status: "error",
            msg: "Internal server error",
          });
        }

        if (result.length > 0) {
          var changePasswordToken = uuid();
          var sent = await sendEmail(email, changePasswordToken);

          if (sent != "0") {
            var data = {
              changePasswordToken: changePasswordToken,
            };

            db.query(
              `UPDATE ${result[0].table_name} SET ? WHERE email = ?`,
              [data, email],
              function (err, result) {
                if (err) {
                  console.error(err);
                  return res.status(500).json({
                    status: "error",
                    msg: "Internal server error",
                  });
                }
              }
            );

            res.status(200).json({
              status: "success",
              msg: "Link-ul pentru resetare a fost trimis catre adresa dumneavoastra: ",
            });
          } else {
            res.status(500).json({
              status: "error",
              msg: "Eroare la server, va rugam incercati din nou",
            });
          }
        } else {
          res.status(404).json({
            status: "error",
            msg: "Acest Email nu este inregistrat la noi!",
          });
        }
      }
    );
  } catch (error) {
    console.error("ERROR", error.name);
    res.status(500).json({ msg: "Eroare interna server" });
  }
});

/* update password to database */
router.post("/update-password", function (req, res, next) {
  try {
    const token = req.body.token;
    const password = req.body.password;

    db.query(
      `(
          SELECT email, 'Administratori' as table_name FROM Administratori WHERE changePasswordToken = ${db.escape(
        token
      )}
        ) UNION (
          SELECT email, 'Pacienti' as table_name FROM Pacienti WHERE changePasswordToken = ${db.escape(
        token
      )}
        ) UNION (
          SELECT email, 'Doctori' as table_name FROM Doctori WHERE changePasswordToken = ${db.escape(
        token
      )}
        ) UNION (
          SELECT email, 'Ingrijitori' as table_name FROM Ingrijitori WHERE changePasswordToken = ${db.escape(
        token
      )}
        ) UNION (
          SELECT email, 'Supraveghetori' as table_name FROM Supraveghetori WHERE changePasswordToken = ${db.escape(
        token
      )}
        );`,
      function (err, result) {
        if (err) {
          console.error(err);
          return res.status(500).json({
            status: "error",
            msg: "Eroare interna server",
          });
        }

        if (result.length > 0) {
          var saltRounds = 10;
          bcrypt.genSalt(saltRounds, function (err, salt) {
            bcrypt.hash(password, salt, function (err, hash) {
              var data = {
                parola: hash,
              };

              db.query(
                `UPDATE ${result[0].table_name} SET ? WHERE email = ${db.escape(
                  result[0].email
                )}`,
                data,
                function (err, result) {
                  if (err) {
                    console.error(err);
                    return res.status(500).json({
                      status: "error",
                      msg: "Eroare interna server",
                    });
                  }
                }
              );

              res.status(200).json({
                status: "success",
                msg: "Parola dumneavoastra a fost actualizata cu success",
              });
            });
          });
        } else {
          res.status(400).json({
            status: "error",
            msg: "Link invalid, va rugam incercati din nou",
          });
        }
      }
    );
  } catch (error) {
    console.error("ERROR", error.name);
    res.status(500).json({ msg: "Eroare interna server" });
  }
});

module.exports = router;
