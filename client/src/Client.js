const fs = require('fs');
const forge = require('node-forge');
const axios = require('axios');

class Client {
    constructor(options) {
        this.privateKeyFile = options.privateKeyFile;
        this.retryTimeout = options.retryTimeout || 1000;
        this.agent = axios.create({
            baseURL: options.url,
            headers: {
                'Authorization': options.secret || 'potato'
            }
        });
    }

    registerKey(key, res, rej) {
        fs.writeFile(this.privateKeyFile, key, (err) => {
            rej(err);
        });

        res();
    }

    fetchKey() {
        return fs.readFileSync(this.privateKeyFile, 'utf8');
    }

    decryptKey(key, encryptedToken, res, rej) {
        let decryptedToken = forge.util.decodeUtf8(key.decrypt(encryptedToken));

        if (decryptedToken) {
            res(decryptedToken);
        } else {
            rej(new Error('Invalid token'));
        }
    }

    register(serviceID) {
        return new Promise(async (res, rej) => {

            let keyPair = await forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });

            let publicKey = Buffer.from(forge.pki.publicKeyToPem(keyPair.publicKey)).toString('base64');
            let privateKey = forge.pki.privateKeyToPem(keyPair.privateKey);

            this.agent.post('/register', { publicKey }, {
                params: {
                    serviceID
                }
            }).then(() => {
                this.registerKey(privateKey, res, rej);
            }).catch(() => {
                setTimeout(() => {
                    this.agent.post('/register', { publicKey }, {
                        params: {
                            serviceID
                        }
                    }).then(() => {
                        this.registerKey(privateKey, res, rej);
                    }).catch(err => {
                        if (err.response) {
                            if (err.response.status === 400) {
                                rej(new Error(err.response.body));
                            } else {
                                rej(new Error(err.response.statusText));
                            }
                        } else if (err.request) {
                            rej(new Error('No response received'));
                        }
                    });
                }, this.retryTimeout);
            });
        });
    }

    getToken(serviceID) {
        return new Promise((res, rej) => {
            this.agent.get('/token', {
                params: {
                    serviceID
                }
            }).then(response => {
                this.respondWithChallenge(serviceID, response.data.challenge, res, rej);
            }).catch(() => {
                setTimeout(() => {
                    this.agent.get('/token', {
                        params: {
                            serviceID
                        }
                    }).then(response => {
                        this.respondWithChallenge(serviceID, response.data.challenge, res, rej);
                    }).catch(err => {
                        if (err.response) {
                            if (err.response.status === 400) {
                                rej(new Error(err.response.body));
                            } else {
                                rej(new Error(err.response.statusText));
                            }
                        } else if (err.request) {
                            rej(new Error('No response received'));
                        }
                    });
                }, this.retryTimeout);
            });
        });
    }

    respondWithChallenge(serviceID, challenge, res, rej) {
        let fetchedKey = this.fetchKey();
        let key = forge.pki.privateKeyFromPem(fetchedKey);
        let md = forge.md.sha1.create().update(challenge, 'utf8');
        let signature = key.sign(md);

        this.agent.post('/token', {
            challenge: signature
        }, {
            params: {
                serviceID
            }
        }).then(response => {
            this.decryptKey(key, response.data.token, res, rej);
        }).catch(() => {
            setTimeout(() => {
                this.agent.post('/token', {
                    challenge: signature
                }, {
                    params: {
                        serviceID
                    }
                }).then(response => {
                    this.decryptKey(key, response.data.token, res, rej);
                }).catch(err => {
                    if (err.response) {
                        if (err.response.status === 400) {
                            rej(new Error(err.response.data));
                        } else {
                            rej(new Error(err.response.data ? err.response.data : err.response.statusText));
                        }
                    } else if (err.request) {
                        rej(new Error('No response received'));
                    }
                });
            }, this.retryTimeout);
        });
    }
}

module.exports = Client;