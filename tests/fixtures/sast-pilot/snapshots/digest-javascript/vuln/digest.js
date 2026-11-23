const crypto = require("node:crypto");

exports.fingerprint = function(data) {
    return crypto.createHash("md5").update(data).digest();
};
