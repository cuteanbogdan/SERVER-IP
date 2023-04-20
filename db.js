var mysql = require('mysql2');

let connection = mysql.createConnection({
    // In PROD this will be with ENV variables
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'aal'
});

connection.connect(function(err) {
    if (err) {
      return console.error('error: ' + err.message);
    }
  
    console.log('Connected to the MySQL server.');
  });

  module.exports = connection;
