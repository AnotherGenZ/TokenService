const Client = require('./src/Client');

function TokenClient(...args) {
    return new Client(...args);
}

module.exports = TokenClient;