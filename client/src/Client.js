const fs = require('fs');
const forge = require('node-forge');
const axios = require('axios');

class Client {
    constructor(options) {
        this.privateKeyFile = options.privateKeyFile;
    }

    register(serviceID) {

    }

    async getToken(serviceID) {

    }
}

module.exports = Client;