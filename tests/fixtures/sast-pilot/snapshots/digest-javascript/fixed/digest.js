const crypto = require("node:crypto");

exports.fingerprint = function(data) {
    return crypto.createHash("sha256").update(data).digest();
};
