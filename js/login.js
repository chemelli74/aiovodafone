var sys_trying_times = 0;
var salt = "";
var credential_detail = false;
var fogotten_password_enable = true;

//init page
function page_init() {
  eaa_set_isAnnouncingAction(false);
  $("div#wrap").focus();

  load_multi_lang_data();

  var html = "";
  html += '<div id="activation-content-left">';
  html += '<img src="img/easybox-2.5.jpg" alt="Router">';
  html += "</div>";
  $("div#activation-content-right").before(html);

  html = "";

  html += '<div class="description">';
  html += '<div class="left" tid="0" al="ACTIVATION_PAGE_STEP_48_SUBTITLE">';
  html += getHTMLString("ACTIVATION_PAGE_STEP_48_SUBTITLE");
  html += "</div>";
  html += "</div>";

  html += '<div class="row description">';
  html += '<div class="left">';
  html +=
    '<input type="text" value="" placeholder="' +
    getHTMLString("ACTIVATION_PAGE_STEP_48_PLACEHOLDER_USERNAME") +
    '" tid="0" al="ACTIVATION_PAGE_STEP_48_PLACEHOLDER_USERNAME">'; //Username
  html += "</div>";
  html += "</div>";
  html += '<div class="row">';
  html += '<div class="left">';
  html +=
    '<input type="password" placeholder="' +
    getHTMLString("ACTIVATION_PAGE_STEP_48_PLACEHOLDER_PASSWORD") +
    '" value="" tid="0" al="ACTIVATION_PAGE_STEP_48_PLACEHOLDER_PASSWORD">'; //Password
  html += "</div>";
  html += '<div class="left">';
  html +=
    '<input type="button" class="button button-apply button-apply-wide" value="' +
    getHTMLString("ACTIVATION_PAGE_STEP_48_LOG_IN") +
    '" tid="0" al="ACTIVATION_PAGE_STEP_48_LOG_IN"/>';
  html += "</div>";
  html += "</div>";

  if (credential_detail) {
    html += '<div class="description" style="clear: both;">';
    html +=
      '<div class="left credential-detail" tid="0" al="ACTIVATION_PAGE_STEP_50_ACCESS_CREDENTIAL_TITLE">' +
      getHTMLString("ACTIVATION_PAGE_STEP_50_ACCESS_CREDENTIAL_TITLE") +
      "</div>"; //Where can I find the access credentials?
    html += "</div>";
  } else {
    if (fogotten_password_enable) {
      html += '<div class="row description">';
      html += '<div class="right">';
      html +=
        '<input class="button button-cancel button-wide forgotten-password" id="start" value="' +
        getHTMLString("ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_BUTTON") +
        '" type="button" tid="0" al="ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_BUTTON">'; //Forgotten Password
      html += "</div>";
      html += "</div>";
    }
  }

  $("div#activation-content-right").attr("style", "");
  $("div#activation-content-right").html(html);
  page_activation_content_right_func_load();

  html = "";
  if (sys_region_code == "sp_else") {
    html +=
      '<li class="language-switcher"><a href="javascript:not_login_lang_change(\'sp_eles\');" tid="0" alm="Español">Español</a></li>';
  } else if (sys_region_code == "cz_else") {
    html +=
      '<li class="language-switcher"><a href="javascript:not_login_lang_change(\'cz_eles\');" tid="0" alm="Czech">Czech</a></li>';
  } else {
    html +=
      '<li class="language-switcher"><a href="javascript:not_login_lang_change(\'it_eles\');" tid="0" alm="Italian">Italian</a></li>';
  }
  html +=
    '<li class="language-switcher"><a href="javascript:not_login_lang_change(\'en_eles\');" tid="0" alm="English">English</a></li>';
  $("#language-switcher-list").html(html);

  //fw version & ip4/ip6 addr
  var html_out = "";
  html_out +=
    '<span class="language-string">' +
    getHTMLString(1310025).replace("%s", sys_info.fw_version) +
    "</span><br>"; //Firmware version: %s
  html_out +=
    '<span class="language-string">' +
    getHTMLString(1310026).replace("%s", sys_info.wan_ip4_addr) +
    "</span><br>"; //WAN IPv4 Address: %s
  if (sys_ipv6_status && sys_ipv6_configuration) {
    html_out +=
      '<span class="language-string">' +
      getHTMLString(1310027).replace("%s", sys_info.wan_ip6_addr) +
      "</span>"; //WAN IPv6 Address: %s
  }
  $("#info").html(html_out);

  //browser support
  if (!isBrowserDetectSupport()) {
    window.parent.location = "nbrow.html";
  }

  var laenge = $("h1:not(.not) span").text().length;
  if (laenge >= 27) {
    $("h1").addClass("twoLines");
  }

  $(".popup .button-cancel").click(function () {
    $(".popup, .blackBackground").fadeOut(function () {
      _addEAA2Destination($("body"), true);
    });
  });

  $(".checkbox").click(function () {
    $(this).toggleClass("checkbox-checked checkbox-unchecked");
    eaa_announceCheckboxState(this);
  });

  $(document).keydown(function (event) {
    if (event.keyCode == 13) {
      processEnterFunc($(".button-apply"));
    }
    if (event.keyCode == 9) {
      //tab key
    }
  });

  transHTMLString();

  _addEAA2Destination($("body"), true);

  /*
			// check if old browsers
			console.log("browser: "+ navigator.userAgent);
			
			var indexoffirefox = navigator.userAgent.toLowerCase().indexOf('firefox');
			if (indexoffirefox > -1){
			  var browser = navigator.userAgent.substring(navigator.userAgent.toLowerCase().indexOf('firefox'));
			  var versionstr = browser.substring(browser.indexOf('/') + 1);			  
			  var version = parseInt(versionstr, 10);		        
			  if (version <= 11){
			  	$("#activation-content-left > img").addClass("olderBrowserIssue");		      	
			  	$(".popup").addClass("olderBrowserIssue");		      	
			  }
			}
			var indexofsafari = navigator.userAgent.toLowerCase().indexOf('safari');
			if (indexofsafari > -1){
			  var browser = navigator.userAgent.substring(navigator.userAgent.toLowerCase().indexOf('safari'));
			  var versionstr = browser.substring(browser.indexOf('/') + 1);			  
			  var version = parseInt(versionstr, 10);		        
			  if (version <= 8){
			  	$("#activation-content-left > img").addClass("olderBrowserIssue");		      	
			  	$(".popup").addClass("olderBrowserIssue");		      	
			  }
			}
			*/

  setTimeout(function () {
    eaa_set_isAnnouncingAction(true);
    window.document.body.focus();
  }, 200);
  processDelayTime();
}

function processEnterFunc(obj) {
  $("input[type=text], input[type=password]").removeClass("input-error");

  var tmp_disabled = obj.attr("disabled");
  if (tmp_disabled != true) {
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
        sys_encryption_key = getUserData("encryption_key", data);
        sys_jump_to_wizard = getUserData("jump_to_wizard", data);

        for (var key in data) {
          if (data[key].salt !== undefined) {
            salt = data[key].salt;
            if (logMessage && window.console)
              console.log("2.get salt: " + salt);
          }
        }

        // make dk
        var passwordSalt = sjcl.codec.hex.toBits(salt);
        var derivedKey = sjcl.misc.pbkdf2(
          $('input[type="password"]').val(),
          passwordSalt,
          1000,
          128,
        );
        //var derivedKey = sjcl.misc.pbkdf2("", passwordSalt, 1000, 128);
        var dk_hex = sjcl.codec.hex.fromBits(derivedKey);

        // encrypt password
        var hash1_pass = hex_hmac_sha256(
          "$1$SERCOMM$",
          unescape(encodeURIComponent($('input[type="password"]').val())),
        );
        var user_password = hex_hmac_sha256(sys_encryption_key, hash1_pass);

        // encrypt username
        var hash1_username = hex_hmac_sha256(
          "$1$SERCOMM$",
          unescape(encodeURIComponent($('input[type="text"]').val())),
        );
        var user_name = hex_hmac_sha256(sys_encryption_key, hash1_username);

        var data_format = [
          { nameObj: LoginName, value: user_name },
          { nameObj: LoginPWD, value: user_password },
        ];
        setCookie("login_uid", Math.random(), 1);
        setWebStorage("dk", dk_hex);
        if (logMessage && window.console)
          console.log("1. set dk: " + dk_hex + " salt: " + salt);
        dataBatchSend(data_format, loginUserLoginRet, "login");

        function loginUserLoginRet(data, textStatus, jqXHR) {
          $("div#message").remove();
          var status = data.slice(0, 3);
          if (status == '"1"' || status == "[ ]") {
            //setCookie("username",user_name,1);
            if (sys_jump_to_wizard == "1")
              window.location.href = "activation.html?mode=basic&step=115";
            else window.location.href = "overview.html";
          } else if (status == '"2"') {
            var html = "";
            html += '<div id="message" class="row description">';
            html +=
              '<div class="message info message-info left"><span id="lang809017">' +
              getHTMLString(809017) +
              "</span></div>"; //A user is logged into the device.
            html += "</div>";

            var row_length = $("div#activation-content-right .row").length;
            $("div#activation-content-right .row").each(function (key, val) {
              if (key == row_length - 1) $(this).after(html);
            });
            _addEAA2Destination($("div#message"), true);
          } else if (status == '"3"') {
            var html = "";
            html += '<div id="message" class="row description">';
            html += '<div class="message message-error">';
            // peter 06/14 '23 html += '<h2><span>'+getHTMLString(1310000)+'</span></h2>'; //Wrong username or password
            // html += '<p></p>';
            html += '<div class="message-error-text">';
            html +=
              '<span id="lang1310001">' + getHTMLString(1310001) + "</span>"; //The username or password you entered was incorrect.
            html += "</div>";
            html += "</div>";
            html += "</div>";

            var row_length = $("div#activation-content-right .row").length;
            $("div#activation-content-right .row").each(function (key, val) {
              if (key == row_length - 1) $(this).after(html);
            });
            _addEAA2Destination($("div#message"), true);

            $("input[type=text], input[type=password]").addClass("input-error");
          } else if (status == '"4"') {
            var html = "";
            html += '<div id="message" class="row description">';
            html += '<div class="message message-error">';
            // peter 06/14 '23 html += '<h2><span>'+getHTMLString(1310000)+'</span></h2>'; //Wrong username or password
            // html += '<p></p>';
            html += '<div class="message-error-text">';
            html +=
              '<span id="lang1310001">' + getHTMLString(1310001) + "</span>"; //The username or password you entered was incorrect.
            html += "</div>";
            html += "</div>";
            html += "</div>";

            var row_length = $("div#activation-content-right .row").length;
            $("div#activation-content-right .row").each(function (key, val) {
              if (key == row_length - 1) $(this).after(html);
            });
            _addEAA2Destination($("div#message"), true);

            $("input[type=text], input[type=password]").addClass("input-error");
          } else if (status == '"5"') {
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
                    if (logMessage && window.console)
                      console.log("3.get salt: " + salt);
                  }
                }

                processDelayTime();
              },
            });
          } else {
            var html = "";
            html += '<div id="message" class="row description">';
            html +=
              '<div class="message message-error left"><span id="lang802036">' +
              getHTMLString(802036) +
              "</span></div>"; //The passwords you entered do not match.
            html += "</div>";

            var row_length = $("div#activation-content-right .row").length;
            $("div#activation-content-right .row").each(function (key, val) {
              if (key == row_length - 1) $(this).after(html);
            });
            _addEAA2Destination($("div#message"), true);
          }
        }
      },
    });
  }
}

function processDelayTime() {
  if (logMessage && window.console)
    console.log("processDelayTime(): " + sys_delay_time + " " + sys_lang_code);

  if (sys_delay_time > 0) {
    if (logMessage && window.console) console.log("delay " + sys_delay_time);

    $(".button-apply").attr("disabled", "disabled");

    //set image
    var t2 = new Image();
    t2.src = "img/icon-thinking.gif";
    t2.id = "progress-bar-thinking-icon";
    //
    $("body, html").animate({ scrollTop: "0px" });

    $(".popup").html(page_login_delay_time_HTMLstr());
    document.getElementById("progress-bar-thinking-box").appendChild(t2);

    var tmp_text = $(".popup span#lang1300086").text();
    tmp_text = tmp_text.replace("%s1", sys_trying_times);
    tmp_text = tmp_text.replace("%s2", sys_delay_time);
    $(".popup span#lang1300086").text(tmp_text);

    $(".popup, .blackBackground").fadeIn(function () {
      removeEaaTidEvents($("body"));
      _addEAA2Destination($(".popup"), true);
      eaa_loopTabKey($(".popup"));
    });
    processDelayFunc(sys_trying_times, sys_delay_time);
  }
}

function processDelayFunc(trying_times, delay_time) {
  //set image
  var t2 = new Image();
  t2.src = "img/icon-thinking.gif";
  t2.id = "progress-bar-thinking-icon";
  //
  setTimeout(function () {
    delay_time = parseInt(delay_time, 10) - 1;
    if (delay_time > 0) {
      $(".popup").html(page_login_delay_time_HTMLstr());
      document.getElementById("progress-bar-thinking-box").appendChild(t2);

      var tmp_text = $(".popup span#lang1300086").text();
      tmp_text = tmp_text.replace("%s1", trying_times);
      tmp_text = tmp_text.replace("%s2", delay_time);
      $(".popup span#lang1300086").text(tmp_text);
      _addEAA2Destination($("div#activation-content-right"), true);

      processDelayFunc(trying_times, delay_time);
    } else {
      if (logMessage && window.console) console.log("delay end");
      $(".popup, .blackBackground").fadeOut(function () {
        _addEAA2Destination($("body"), true);
        $(".button-apply").focus();
      });
      $(".button-apply").removeAttr("disabled");
    }
  }, 1000);
}

function page_login_delay_time_HTMLstr() {
  var html = "";
  html +=
    '<p class="title"><span id="lang1300086">' +
    getHTMLString(1300086) +
    "</span></p>"; //You are trying to login with wrong password for %s1 times, please wait %s2 seconnds to enter new password
  html += '<div class="row">';
  html += '<div id="progress-bar-thinking-box">';
  //html += '<img id="progress-bar-thinking-icon" src="img/icon-thinking.gif">';
  html += "</div>";
  html += "</div>";

  return html;
}

function popupClose() {
  document.getElementById("popup").style.display = "none";
  document.getElementById("blackBackground").style.display = "none";
  _addEAA2Destination($("body"), true);
}
//init page end
/*
 * function for textfields
 * to have a placeholder
 * which is only visible if
 * textfield is "empty"
 */
function tglInput(obj, value) {
  if (obj.hasClass("active")) {
    if (obj.val() == "") {
      obj.val(value);
      obj.toggleClass("active");
    }
  } else {
    if (obj.val() == value) {
      obj.val("");
      obj.toggleClass("active");
    }
  }
}

$(document).ready(function () {
  if (!isBrowserDetectSupport()) {
    top.location.href = "nbrow.html";
  }
  if (!areCookiesEnabled()) {
    window.parent.location = "ncoki.html"; //no cookie
  }

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
      //Invalid filter
      data = filterInvalidString(data);

      usermode = getUserData("usermode", data);
      sys_phone_service = getUserData("phone_service", data);
      sys_username = getUserData("username", data);
      sys_dropDownBasExp = getUserData("dropDownBasExp", data);
      sys_pageid = getUserData("pageid", data);
      sys_lang_code = getUserData("lang_code", data);
      sys_region_code = getUserData_string(
        "region_code",
        data,
        sys_region_code,
      );
      sys_delay_time = getUserData("delay_time", data);
      sys_encryption_key = getUserData("encryption_key", data);
      sys_ipv6_status = getUserData("ipv6_status", data);
      sys_ipv6_configuration = getUserData("ipv6_configuration", data);
      sys_info.fw_version = getUserData("fw_version", data);
      sys_info.wan_ip4_addr = getUserData("wan_ip4_addr", data);
      sys_info.wan_ip6_addr = getUserData("wan_ip6_addr", data);

      for (var key in data) {
        if (data[key].trying_times !== undefined) {
          sys_trying_times = data[key].trying_times;
        }
        if (data[key].salt !== undefined) {
          salt = data[key].salt;
          if (logMessage && window.console) console.log("1.get salt: " + salt);
        }
        if (data[key].credential_detail !== undefined) {
          credential_detail = data[key].credential_detail === "1";
        }
        if (data[key].password_enable !== undefined) {
          fogotten_password_enable = data[key].password_enable === "1";
        }
      }

      if (sys_lang_code == "") {
        if (usermode == "admin") {
          sys_lang_code = "en_eles";
        } else {
          if (sys_region_code == "sp_else") {
            sys_lang_code = "sp_eles";
          } else if (sys_region_code == "cz_else") {
            sys_lang_code = "cz_eles";
          } else {
            sys_lang_code = "it_eles";
          }
        }
      }

      page_init();
    },
  });
});

function page_activation_content_right_func_load() {
  $(".button-apply").click(function () {
    processEnterFunc($(".button-apply"));
  });

  $(".forgotten-password").on("click", function () {
    if (false && window.console) console.log(".forgotten-password click");

    var html = "";
    html += '<div class="mobile-cancel-popup button-cancel"></div>';

    html += '<div class="task1ForStep5">';
    html +=
      '<h1 class="tL"><span class="language-string" name="ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_POPUP_TITLE">' +
      getHTMLString("ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_POPUP_TITLE") +
      "</span></h1>"; //Password Reset
    html += '<div class="description">';
    html += '<div class="left">';
    html +=
      '<span class="language-string" name="ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_POPUP_SUBTITLE">' +
      getHTMLString(
        "ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_POPUP_SUBTITLE",
      ) +
      "</span>"; //Click the Reset button and follow the instructions that you will receive by mail.
    html += "</div>";
    html += "</div>";
    html += "</div>";

    html += '<div class="task2ForStep5" style="display:none">';
    html +=
      '<h3><span class="language-string" name="ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_POPUP_TITLE">' +
      getHTMLString("ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_POPUP_TITLE") +
      "</span></h3>"; //Password Reset
    html += '<div class="description">';
    html += '<div class="left">';
    html +=
      '<span class="language-string" name="ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_STEP_2_SUBTITLE">' +
      getHTMLString(
        "ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_STEP_2_SUBTITLE",
      ) +
      "</span>"; //The email with the instructions for resetting the password was sent.
    html += "</div>";
    html += "</div>";
    html += '<div class="row description noLeftPadding">';
    html += '<div class="right">';
    html +=
      '<input class="button button-cancel" value="Ok" type="button" tid="0" alm="Ok">'; //Ok
    html += "</div>";
    html += "</div>";
    html += "</div>";

    html += '<div class="task1ForStep5">';
    html += '<div class="row description noLeftPadding">';
    html += '<div class="right">';
    html +=
      '<input class="button button-apply resetButton" value="' +
      getHTMLString(
        "ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_POPUP_RESET_BUTTON",
      ) +
      '" type="button" tid="0" al="ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_POPUP_RESET_BUTTON"> '; //Reset
    html +=
      '<input class="button button-cancel task1ForStep5" value="' +
      getHTMLString(
        "ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_POPUP_CANCEL_BUTTON",
      ) +
      '" type="button" tid="0" al="ACTIVATION_PAGE_STEP_48_FORGOTTEN_PASSWORD_POPUP_CANCEL_BUTTON">'; //Cancel
    html += "</div>";
    html += "</div>";
    html += "</div>";

    $(".popup").html(html);

    $("body, html").animate({ scrollTop: "0px" });
    $(".popup, .blackBackground").fadeIn(function () {
      removeEaaTidEvents($("body"));
      _addEAA2Destination($(".popup"), true);
      eaa_loopTabKey($(".popup"));
    });

    $(".popup .button-apply").on("click", function () {
      if (false && window.console) console.log(".button-apply click");

      var data_format = [{ nameObj: loginResetPassword, value: "1" }];

      dataBatchSend(data_format, loginResetPasswordRet, "resetpwd");
    });

    $(".popup .button-cancel").on("click", function () {
      if (false && window.console) console.log(".button-cancel click");

      $(".popup, .blackBackground").fadeOut(function () {
        _addEAA2Destination($("body"), true);
        $(".forgotten-password").focus();
      });
    });
  });

  $(".credential-detail").on("click", function () {
    if (false && window.console) console.log(".credential-detail click");

    var html = "";
    html += '<div class="mobile-cancel-popup button-cancel"></div>';
    html += '<div class="task1ForStep5">';
    html +=
      '<h1 class="tL"><span class="language-string" name="ACTIVATION_PAGE_STEP_50_ACCESS_CREDENTIAL_POPUP_TITLE">' +
      getHTMLString("ACTIVATION_PAGE_STEP_50_ACCESS_CREDENTIAL_POPUP_TITLE") +
      "</span></h1>"; //Where can I find the access credentials?
    html += '<div id="credential-detail-popup-image">';
    html +=
      '<img src="/img/look_4/activation/access_credentials.png" alt="Router">';
    html += "</div>";
    html += '<div class="description">';
    html +=
      '<div class="left popup-discription tL"><span class="language-string" name="ACTIVATION_PAGE_STEP_50_ACCESS_CREDENTIAL_POPUP_SUBTITLE">' +
      getHTMLString(
        "ACTIVATION_PAGE_STEP_50_ACCESS_CREDENTIAL_POPUP_SUBTITLE",
      ) +
      "</span></div>"; //Utilize your access credentials (Utente and Router Password) written on the label at bottom side of your Vodafone Power Station.
    html += "</div>";
    html += "</div>";
    html += '<div class="row description noLeftPadding">';
    html += '<div class="right">';
    html +=
      '<input type="button" class="button button-cancel" value="' +
      getHTMLString(
        "ACTIVATION_PAGE_STEP_50_ACCESS_CREDENTIAL_POPUP_OK_BUTTON",
      ) +
      '" tid="0" al="ACTIVATION_PAGE_STEP_50_ACCESS_CREDENTIAL_POPUP_OK_BUTTON">';
    html += "</div>";
    html += "</div>";

    $(".popup").html(html);

    $("body, html").animate({ scrollTop: "0px" });
    $(".popup, .blackBackground").fadeIn(function () {
      removeEaaTidEvents($("body"));
      _addEAA2Destination($(".popup"), true);
      eaa_loopTabKey($(".popup"));
    });

    $(".popup .button-cancel").on("click", function () {
      if (false && window.console) console.log(".button-cancel click");

      $(".popup, .blackBackground").fadeOut(function () {
        _addEAA2Destination($("body"), true);
        $(".credential-detail").focus();
      });
    });
  });
}

function loginResetPasswordRet(data, textStatus, jqXHR) {
  if (data == "1") {
    $(".popup .task1ForStep5").hide();
    $(".popup .task2ForStep5").show();
    _addEAA2Destination($(".popup"), true);
    eaa_loopTabKey($(".popup"));
  }
}

function areCookiesEnabled() {
  var cookieEnabled = navigator.cookieEnabled;

  // When cookieEnabled flag is present and false then cookies are disabled.
  if (cookieEnabled === false) {
    return false;
  }

  // try to set a test cookie if we can't see any cookies and we're using
  // either a browser that doesn't support navigator.cookieEnabled
  // or IE (which always returns true for navigator.cookieEnabled)
  if (!document.cookie && (cookieEnabled === null || /*@cc_on!@*/ false)) {
    document.cookie = "testcookie=1";

    if (!document.cookie) {
      return false;
    } else {
      document.cookie = "testcookie=; expires=" + new Date(0).toUTCString();
    }
  }

  return true;
}
