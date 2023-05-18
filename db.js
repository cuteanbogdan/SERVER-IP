var mysql = require('mysql2');
var fs = require('fs');

let connection = mysql.createConnection({
  // In PROD this will be with ENV variables
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
  port: 3306,
  ssl: { ca: fs.readFileSync("./DigiCertGlobalRootCA.crt.pem") }
});

connection.connect(function (err) {
  if (err) {
    return console.error('error: ' + err.message);
  }

  console.log('Connected to the MySQL server on Azure.');
});

module.exports = connection;