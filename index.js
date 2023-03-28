const express = require('express')
const app = express()
const dotenv = require('dotenv')
dotenv.config()
let db = require('./db');
const port = process.env.PORT || 5000



app.get('/', (req, res) => {
    res.send('Hello World!')
})

//temp test on DB
db.query(
    'SELECT * FROM `users_table`',
    function(err, results, fields) {
      console.log(results); // results contains rows returned by server
    }
  );

app.listen(port, () => {
    console.log(`Server listening on port ${port}`)
})