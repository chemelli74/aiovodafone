//Get salt from server
$.ajax({
  type: "get",
  dataType: "json",
  url:
    "./data/user_lang.json?_=" +
    new Date().getTime() +
    "&csrf_token=" +
    csrf_token,
  async: false,
  success: function (data) {
    sys_delay_time = getUserData("delay_time", data);
    sys_encryption_key = getUserData("encryption_key", data);

    for (var key in data) {
      if (data[key].trying_times !== undefined) {
        sys_trying_times = data[key].trying_times;
      }
      if (data[key].salt !== undefined) {
        salt = data[key].salt;
        if (logMessage && window.console) console.log("3.get salt: " + salt);
      }
    }

    processDelayTime();
  },
});

// Calculate derived key using SJCL PBKDF2
var passwordSalt = sjcl.codec.hex.toBits(salt);
var derivedKey = sjcl.misc.pbkdf2(
  $('input[type="password"]').val(),
  passwordSalt,
  1000,
  128,
);
var dk_hex = sjcl.codec.hex.fromBits(derivedKey);
setWebStorage("dk", dk_hex);

// Decrypt
data = sjcl.decrypt(getWebStorage("dk"), data);

// Encrypt
in_data = sjcl.encrypt(getWebStorage("dk"), in_data, {
  iter: 1000,
  iv: sjcl.random.randomWords(3, 0),
});
