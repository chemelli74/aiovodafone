const sjcl = require("./sjcl-beautified");

var password = "D8QLRCEGG4L2";
var salt = "02446aa702b651de";

var passwordSalt = sjcl.codec.hex.toBits(salt);
var derivedKey = sjcl.misc.pbkdf2(password, passwordSalt, 1000, 128);
var dk_hex = sjcl.codec.hex.fromBits(derivedKey);

console.log("1. set dk: " + dk_hex + " salt: " + salt);

data_enc = "pippo";
data = sjcl.encrypt(data_enc, dk_hex);
console.log("2. encrypted data: " + data);
