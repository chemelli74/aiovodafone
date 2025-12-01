const sjcl = require("./sjcl-beautified");

var password = "D8QLRCEGG4L2";
var salt = "4F2F18495E52D2C3";

var passwordSalt = sjcl.codec.hex.toBits(salt);
var derivedKey = sjcl.misc.pbkdf2(password, passwordSalt, 1000, 128);
var dk_hex = sjcl.codec.hex.fromBits(derivedKey);

console.log("1. set dk: " + dk_hex + " salt: " + salt);

data_enc =
  '{  "iv": "axY/8UgKXQw=", "v": 1, "iter": 1000, "ks": 128, "ts": 64, "mode": "ccm",        "adata": "",        "cipher": "aes",        "salt": "fjEmrVTeYgA=",        "ct": "g+m9SdWSiH+3t06zNHhh5WoG/ZTvi/276a66hK0teIJroYXqQJGDcxwr1TYcGiv9r54xTv1hC9S05M1s8RA5f1cnewEI1UBdRHNbWKfUOW3GnWY16DfUOJNu1RmqpBtSCRfVxkRqzp1jH9zqlk4Epi0XYy1YisjIQhE+8F5NDKvT6QdHiF4DkvXKvboQXNiazeJ1H/I2WQtMIP3oMrWd6nJvWYq8X5UafDhArmyoR+4NPfjx3pWxt1tCGQ4lmz9y8QPZVnHD1t7K/q12IQB3CxPHF4RkxSYhRtsasAQo1XL4cHfIp953OvDoxI0dAdhBrk2mf3gLuiMT482oyjv00lHa507KQ9on1YnZWJT9ld5JWsAeo+4iaVrXYor/OqUCJWOiUsSkh+uvAi6AzB1iO50FCdcGMHa0BXRrwuamf21q1CCuM2wQo7he7xEY29BnhinlHZ4Zqal5UFpR/EAR9PWvcx/Lv3ULRcZzmJRxUyWbiiNSMgBARa+5224+FyMLMh4doHZoiP2kLv2kUd2Iu99Nomykouw49y8cILv0bDVGLIRMDlo80whE8qCwNVxUabINOfBfyB5TbZF5m1RzPuW6XvGXRd/cZCpCyoOLAptml8LEVzTUbiKb+Fo27psBMF8zGtDwUA4Lzw8v/VTHdDndx0d2X0WloyQ5ch6w2I3ezkZMhKhQ2WLHEPVM4ffioqw+e58tBkj8BUsbh4EzrEUehXu7CWqBZDXP9OAY4wUP3NIm0rp593I30eoxdhLlFiWjEkjWx0eJzuvbQ5m9Ep+ELyIceWS9CHwJCGqCP0fgid0zxTm2rle7CFMnod9genbs6v6SkKJ3JND0yyYVeXRyXUEQrkM6/+YhzNaCNu7nx9fREOOrNsG2azVFlu+n/XF0IGJN7ow7O1mukpJhbDSEi3bCloaNlBA2EcbWKKqstnrX6Skep3L1Dknt0Mml7TkwJjoRr7cnayLLGrE+P07B9WD2eY/f0Oc2e/JoQJJChnEbddxFWn3CPHuKxFQyg7biw4EfXuBh5snfOXsc5+CYFk7PiTlLo/0FGyNM64ibPM1H13aeZ27nz3caT+HoyG6XbsR1IFqqPjyh17QsoRcmsLfT/F05889l5jaUfp5NxM3YadNhUFAm+jWnFEwGgeMb7JhnXANcKnd7vMgptAKE71vayX3i4OOos3JMucqtzZ6ZU8asUxtoesL+xF1WYJuwVynwFHNl9UEf7yiuwqalgSCQ3onAEWdInxrdH6IP+fOBA7fy+xt7SVti/tTCPOHoa+enlIe2bKovEssRljSA8+fB0hXBZRtBnIXc3IcCQYdFQkm3rAnmHNDam0lk+265ilLA8LVxa36nuR/yk7JjLk+NawLOP65fpdAzDoIiympvcmTuRNov3PZqOV6M1DQd6UmBKt3uxOgctWxNIFl+7HR71krNtHwjQyiNGQkSEYZ8V6XvGfFlENyGKk/8pOVGGbn6qCaiMbjdfyiSRXyGj8/dAFTJM2hukVyMxsMaFghkMCpQ7IcSPA1RCCR6bBQJGPcZOFIvMzqpmhJDbeuj5UmOlghm0UAwoNYn3g==" }';
data = sjcl.decrypt(dk_hex, data_enc);
console.log("2. encrypted data: " + data);
