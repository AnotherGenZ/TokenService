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
        fs.writeFile(this.privateKeyFile, Buffer.from(key, 'base64').toString('utf8'), (err) => {
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
        return new Promise((res, rej) => {
            this.agent.get('/register', {
                params: {
                    serviceID
                }
            }).then(response => {
                this.registerKey(response.data.key, res, rej);
            }).catch(() => {
                setTimeout(() => {
                    this.agent.get('/register', {
                        params: {
                            serviceID
                        }
                    }).then(response => {
                        this.registerKey(response.data.key, res, rej);
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
            params: {
                serviceID
            },
            data: {
                challenge: signature
            }
        }).then(response => {
            this.decryptKey(key, response.data.token, res, rej);
        }).catch(() => {
            setTimeout(() => {
                this.agent.post('/token', {}, {
                    params: {
                        serviceID
                    },
                    data: {
                        challenge: signature
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