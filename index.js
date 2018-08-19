const express = require('express');
const bodyParser = require('body-parser');
require('dotenv').config();

let app = express();

app.use(bodyParser.json());

app.get('/', (req, res) => {
    let auth = req.get('Authorization');

    if (auth && auth === process.env.AUTHORIZATION) {
        return res.status(200).send({ token: Buffer.from(process.env.BOT_TOKEN).toString('base64') });
    } else {
        return res.status(401).end();
    }
});

app.get('/token', (req, res) => {

});

app.post('/token', (req, res) => {

});

app.listen(8080);