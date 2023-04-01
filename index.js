const express = require('express')
const app = express()
const dotenv = require('dotenv')
const bodyParser = require('body-parser');
const cors = require('cors')
dotenv.config()
const db = require('./db');
const port = process.env.PORT || 5000
const indexRouter = require('./router.js')

app.use(express.json());

app.use(bodyParser.json());

app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(cors());
app.get('/', (req, res) => {
    res.send('Hello World!')
})
app.use('/api', indexRouter);


app.listen(port, () => {
    console.log(`Server listening on port ${port}`)
})