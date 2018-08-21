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

    register(serviceID) {
        return new Promise(async (res, rej) => {
            let response = await this.agent.get('/register', {
                params: {
                    serviceID
                }
            }).catch(() => {
                setTimeout(async () => {
                    response = await this.agent.get('/register', {
                        params: {
                            serviceID
                        }
                    }).catch(err => {
                        if (err.response) {
                            if (err.response.status === 400) {
                                rej(new Error(err.response.body));
                            } else if (err.response.status === 401) {
                                rej(new Error(err.response.statusText));
                            } else if (err.response.status === 500) {
                                rej(new Error(err.response.statusText));
                            }
                        } else if (err.request) {
                            rej(new Error('No response received'));
                        }
                    });
                }, this.retryTimeout);
            });

            fs.writeFile(this.privateKeyFile, Buffer.from(response.data.key).toString('ascii'), (err) => {
                rej(err);
            });

            res();
        });
    }

    getToken(serviceID) {
        return new Promise(async(res, rej) => {
            
        });
    }
}

module.exports = Client;