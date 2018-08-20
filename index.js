const express = require('express');
const bodyParser = require('body-parser');
const forge = require('node-rsa');
const level = require('level');
const fs = require('fs');
const https = require('https');
const jwt = require('jsonwebtoken');
let randomstring = require('randomstring');


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
let db = level('./db');

let challenges = new Map();

app.use(bodyParser.json());

app.get('/register', (req, res) => {
    let auth = req.get('Authorization');
    let serviceID = req.query.serviceID;

    if (!serviceID) return res.status(400).send('Missing serviceID');

    if (auth && auth === process.env.AUTHORIZATION) {
        let keyPair;

        try {
            forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 }, (err, keypair) => {
                if (err) throw new Error(err);

                keyPair = keypair;
            });
        } catch (err) {
            console.log(err);
            return res.status(500).end();
        }

        try {
            await db.put(serviceID, {
                private: forge.pki.privateKeyToPem(keyPair.privateKey),
                public: forge.pki.publicKeyToPem(keyPair.publicKey)
            });
        } catch (err) {
            console.log(err);
            return res.status(500).end();
        }

        return res.status(200).send({ key: Buffer.from(forge.pki.privateKeyToPem(keyPair.privateKey)).toString('base64') });
    } else {
        return res.status(401).end();
    }
});

app.get('/token', (req, res) => {
    let serviceID = req.query.serviceID;

    if (!serviceID) return res.status(400).send('Missing serviceID');

    let service = db.get(serviceID);

    if (!service) return res.status(401).send('Unregistered service');

    let challengeString = randomstring.generate({
        length: 50
    });

    let challenge = jwt.sign({ serviceID, challenge: challengeString }, service.private, {
        expiresIn: 60,
        audience: serviceID,
        issuer: 'Dyno TokenService'
    });

    let md = forge.md.sha1.create();
    md.update(challenge, 'utf8');

    challenges.set(serviceID, { challenge: challengeString, md });

    return res.status(200).send({ challenge });
});

app.post('/token', (req, res) => {
    let serviceID = req.query.serviceID;

    if (!serviceID) return res.status(400).send('Missing serviceID');

    let reqChallenge = req.body.challenge;

    if (!reqChallenge) return res.status(400).send('Missing challenge');

    let service = db.get(serviceID);

    if (!service) return res.status(401).send('Unregistered service');

    let challenge = challenges.get(serviceID);

    if (!challenge) return res.status(403).send('No challenge found');

    let verified;

    let publicKey = forge.pki.publicKeyToPem(service.public);

    try {
        verified = publicKey.verify(challenge.md.digest().bytes(), reqChallenge);
    } catch (err) {
        return res.status(401).send('Invalid challenge');
    }

    let decrypted;

    try {
        decrypted = jwt.verify(verified, service.public, {
            audience: serviceID,
            issuer: 'Dyno TokenService'
        });
    } catch (err) {
        return res.status(401).send('Invalid/expired challenge');
    }

    if (decrypted.challenge === challenge.challenge) {
        challenges.delete(serviceID);
        return res.status(200).send({ token: publicKey.encrypt(forge.util.encodeUtf8(process.env.BOT_TOKEN)) });
    } else {
        return res.status(401).send('Challenge mismatch');
    }
});

const httpsServer = https.createServer(credentials, app);

httpsServer.listen(process.env.PORT, () => {
    console.log('HTTPS Server running on port 443');
});