const express = require('express');
const bodyParser = require('body-parser');
const forge = require('node-forge');
const level = require('level');
const fs = require('fs');
const https = require('https');
const jwt = require('jsonwebtoken');
let randomstring = require('randomstring');

let db = level('./db');

require('dotenv').config();

const privateKey = fs.readFileSync(process.env.PRIVATE_KEY, 'utf8');
const certificate = fs.readFileSync(process.env.CERT, 'utf8');
const ca = fs.readFileSync(process.env.CA, 'utf8');

const credentials = {
    key: privateKey,
    cert: certificate,
    ca: ca
};

let app = express();


let challenges = new Map();

app.use(bodyParser.json());

function fetchService(serviceID) {
    return new Promise((res, rej) => {
        db.get(serviceID, (err, value) => {
            if (err) {
                return rej(err);
            }

            res(JSON.parse(value));
        });
    });
}

app.post('/register', async (req, res) => {
    let auth = req.get('Authorization');
    let serviceID = req.query.serviceID;

    if (!serviceID) return res.status(400).send('Missing serviceID');

    let publicKey = req.body.publicKey;

    if (!publicKey) return res.status(400).send('Missing publicKey');

    let existing;

    try {
        await fetchService(serviceID);
        existing = true;
    } catch (err) {
        console.log(err);
        existing = false;
    }

    if (existing) return res.status(403).end();

    if (auth && auth === process.env.AUTHORIZATION) {

        try {
            await db.put(serviceID, JSON.stringify({
                public: Buffer.from(publicKey, 'base64').toString('utf8')
            }));
        } catch (err) {
            console.log(err);
            return res.status(500).end();
        }

        return res.status(200).end();
    } else {
        return res.status(401).end();
    }
});

app.get('/token', async (req, res) => {
    let serviceID = req.query.serviceID;
    let auth = req.get('Authorization');

    if (!auth || auth !== process.env.AUTHORIZATION) return res.status(401).end();

    if (!serviceID) return res.status(400).send('Missing serviceID');

    let service = await fetchService(serviceID);

    if (!service) return res.status(401).send('Unregistered service');

    let challengeString = randomstring.generate({
        length: 50
    });

    let challenge = jwt.sign({ serviceID, challenge: challengeString }, process.env.SECRET, {
        expiresIn: 60,
        audience: serviceID,
        issuer: 'Dyno TokenService'
    });

    let md = forge.md.sha1.create();
    md.update(challenge, 'utf8');

    challenges.set(serviceID, { challenge, challengeString, md });

    return res.status(200).send({ challenge });
});

app.post('/token', async (req, res) => {
    let serviceID = req.query.serviceID;
    let auth = req.get('Authorization');

    if (!auth || auth !== process.env.AUTHORIZATION) return res.status(401).end();

    if (!serviceID) return res.status(400).send('Missing serviceID');

    let reqChallenge = req.body.challenge;

    if (!reqChallenge) return res.status(400).send('Missing challenge');

    let service = await fetchService(serviceID);

    if (!service) return res.status(401).send('Unregistered service');

    let challenge = challenges.get(serviceID);

    if (!challenge) return res.status(403).send('No challenge found');

    let verified;

    let publicKey = forge.pki.publicKeyFromPem(service.public);

    try {
        verified = publicKey.verify(challenge.md.digest().bytes(), reqChallenge);
    } catch (err) {
        return res.status(401).send('Invalid challenge');
    }

    if (!verified) return res.status(401).send('Invalid challenge');

    let decrypted;

    try {
        decrypted = jwt.verify(challenge.challenge, process.env.SECRET, {
            audience: serviceID,
            issuer: 'Dyno TokenService'
        });
    } catch (err) {
        return res.status(401).send('Invalid/expired challenge');
    }

    if (decrypted.challenge === challenge.challengeString) {
        challenges.delete(serviceID);
        return res.status(200).send({ token: publicKey.encrypt(forge.util.encodeUtf8(process.env.BOT_TOKEN)) });
    } else {
        return res.status(401).send('Challenge mismatch');
    }
});

const httpsServer = https.createServer(credentials, app);

httpsServer.listen(process.env.PORT, () => {
    console.log('DynoToken service ready!');
});

/* app.listen(process.env.PORT, () => {
    console.log('App ready');
}); */

process.on('uncaughtException', (err) => {
    console.log(err);
});

process.on('unhandledRejection', (reason, p) => {
    console.log(`Unhandled rejection at: Promise  ${p} reason:  ${reason.stack}`);
});