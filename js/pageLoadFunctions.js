function page_data_load(page) {
  if (chkUserDataModification()) return false;

  //activation
  if (page == "activation") {
    page_activation_load();
    return true;
  }

  if (
    page == "overview" ||
    page == "phone" ||
    page == "internet" ||
    page == "wifi" ||
    page == "messages" ||
    page == "sharing" ||
    page == "settings" ||
    page == "status-and-support"
  ) {
    loginUserChkLoginTimeout.set(
      sys_username,
      loginUserChkLoginTimeoutRet,
      "login",
    );

    setTimeout(function () {
      //waiting page id changed
      if (page == "overview") {
        var JSONSource =
          "./data/" +
          page +
          ".json?_=" +
          new Date().getTime() +
          "&csrf_token=" +
          csrf_token;
        $.getJSON(JSONSource, function (data) {
          //Invalid filter
          data = filterInvalidString(data);

          page_data_already_load(page, data);
        });
      } else {
        page_data_already_load(page, null);
      }
    }, 400);
  } else {
    var JSONSource =
      "./data/" +
      page +
      ".json?_=" +
      new Date().getTime() +
      "&csrf_token=" +
      csrf_token;
    $.getJSON(JSONSource, function (data) {
      //Invalid filter
      data = filterInvalidString(data);

      page_data_already_load(page, data);
    });
  }
}

function page_data_already_load(page, data) {
  //reset
  var tmp_id = _get_pages_reset_id_by_hashid(_get_pages_hashid());

  if (
    reset_pages_ary != undefined &&
    tmp_id !== "" &&
    in_array(tmp_id, reset_pages_ary)
  ) {
    $(".resetButtonsShort").show();
    $(".resetBar").hide();
    _addEAA2Destination($("#resetWrap, #resetWrapMobile"), true);
  } else {
    $(".resetButtonsShort").hide();
    $(".resetBar").hide();
    _addEAA2Destination($("#resetWrap, #resetWrapMobile"), true);
  }
  //reset end

  //overview
  if (page == "overview") page_overview_load(data);

  //phone
  if (page == "phone") page_phone_load();
  if (page == "phone_call_log") page_phone_call_log_load(data);
  if (page == "phone_contacts") page_phone_contacts_load(data);
  if (page == "phone_wake_up_call") page_phone_wake_up_call_load(data);
  if (page == "phone_ringing_schedule") page_phone_ringing_schedule_load(data);
  if (page == "phone_phone_settings") page_phone_phone_settings_load(data);

  //internet
  if (page == "internet") page_internet_load();
  if (page == "internet_port_mappin") page_internet_port_mappin_load(data);
  if (page == "internet_dmz") page_internet_dmz_load(data);
  if (page == "internet_parental_control")
    page_internet_parental_control_load(data);

  //wifi
  if (page == "wifi") page_wifi_load();
  if (page == "wifi_general") page_wifi_general_load(data);
  if (page == "wifi_wps") page_wifi_wps_load(data);

  //Messages
  if (page == "messages") page_messages_load();

  //sharing
  if (page == "sharing") page_sharing_load();

  //settings
  if (page == "settings") page_settings_load();
  if (page == "settings_password") page_settings_password_load(data);
  if (page == "settings_configuration") page_settings_configuration_load(data);
  if (page == "settings_fw_update") page_settings_fw_update_load(data);

  //status-and-support
  if (page == "status-and-support") page_statussupport_load();
}

function page_data_send(send_url, in_data, func_back) {
  var input_url =
    send_url + "?_=" + new Date().getTime() + "&csrf_token=" + csrf_token;
  $.post(input_url, in_data, function (data, textStatus, jqXHR) {
    if (logMessage && window.console)
      console.log("post " + input_url + ":" + textStatus);

    if (func_back != null) func_back(data, textStatus, jqXHR);
  });
}

function page_data_send_sjcl(send_url, in_data, func_back) {
  var input_url =
    send_url + "?_=" + new Date().getTime() + "&csrf_token=" + csrf_token;
  $.post(input_url, in_data, function (data, textStatus, jqXHR) {
    if (logMessage && window.console)
      console.log("post " + input_url + ":" + textStatus);

    if (func_back != null) {
      //sjcl decrypt
      if (sys_sjcl_enable) {
        data = sjcl.decrypt(getWebStorage("dk"), data);
      }
      //sjcl decrypt end

      func_back(data, textStatus, jqXHR);
    }
  });
}
function dataBatchSend(obj, func, send_url) {
  var post_type = false && false ? ".php" : ".json";
  if (send_url == undefined) return;
  else send_url = "./data/" + send_url + post_type;
  var in_data = "";

  for (var key in obj) {
    var nameObj = obj[key]["nameObj"];
    var value = obj[key]["value"];
    //Invalid filter
    value = filterInvalidString(value);

    if (key == "0") in_data = nameObj.id + "=" + encodeURIComponent(value);
    else in_data += "&" + nameObj.id + "=" + encodeURIComponent(value);
  }

  //page_data_send(send_url, in_data, func);
  //modify 20131016
  if (usermode == "") {
    //not login
    $.post(
      "./data/reset" +
        post_type +
        "?_=" +
        new Date().getTime() +
        "&csrf_token=" +
        csrf_token,
      "chk_sys_busy=" + encodeURIComponent(sys_username),
      function (data, textStatus, jqXHR) {
        if (data == "1") {
          window.parent.location = "fw_upgrade_progress.html";
        } else {
          page_data_send(send_url, in_data, func);
        }
      },
    );
  } else {
    $.post(
      "./data/reset" +
        post_type +
        "?_=" +
        new Date().getTime() +
        "&csrf_token=" +
        csrf_token,
      "chk_sys_busy=" + encodeURIComponent(sys_username),
      function (data, textStatus, jqXHR) {
        if (data == "1") {
          window.parent.location = "fw_upgrade_progress.html";
        } else {
          loginUserChkLoginTimeout.set(
            sys_username,
            loginUserChkLoginTimeoutRet,
            "login",
          );
          page_data_send(send_url, in_data, func);
        }
      },
    );
  }
  //add end

  return true;
}

function dataBatchSend_sjcl(obj, func, send_url) {
  var post_type = false && false ? ".php" : ".json";
  if (send_url == undefined) return;
  else send_url = "./data/" + send_url + post_type;
  var in_data = "";
  var in_reset_data = "chk_sys_busy=" + encodeURIComponent(sys_username);

  for (var key in obj) {
    var nameObj = obj[key]["nameObj"];
    var value = obj[key]["value"];
    //Invalid filter
    value = filterInvalidString(value);

    if (key == "0") in_data = nameObj.id + "=" + encodeURIComponent(value);
    else in_data += "&" + nameObj.id + "=" + encodeURIComponent(value);
  }

  if (usermode == "") {
    //not login
    $.post(
      "./data/reset" +
        post_type +
        "?_=" +
        new Date().getTime() +
        "&csrf_token=" +
        csrf_token,
      in_reset_data,
      function (data, textStatus, jqXHR) {
        if (data == "1") {
          window.parent.location = "fw_upgrade_progress.html";
        } else {
          page_data_send(send_url, in_data, func);
        }
      },
    );
  } else {
    if (sys_sjcl_enable) {
      in_data = sjcl.encrypt(getWebStorage("dk"), in_data, {
        iter: 1000,
        iv: sjcl.random.randomWords(3, 0),
      });
      //in_reset_data = sjcl.encrypt(getWebStorage("dk"), in_reset_data, {iter:1000, iv:sjcl.random.randomWords(3,0)});
    }

    $.post(
      "./data/reset" +
        post_type +
        "?_=" +
        new Date().getTime() +
        "&csrf_token=" +
        csrf_token,
      in_reset_data,
      function (data, textStatus, jqXHR) {
        if (data == "1") {
          window.parent.location = "fw_upgrade_progress.html";
        } else {
          //loginUserChkLoginTimeout.set_sjcl(sys_username, loginUserChkLoginTimeoutRet, 'login');
          loginUserChkLoginTimeout.set(
            sys_username,
            loginUserChkLoginTimeoutRet,
            "login",
          );
          page_data_send(send_url, in_data, func);
        }
      },
    );
  }

  return true;
}

function hmacSHA1_sjcl(key) {
  var hasher = new sjcl.misc.hmac(key, sjcl.hash.sha1);
  this.encrypt = function () {
    return hasher.encrypt.apply(hasher, arguments);
  };
}

function randomStr_sjcl(isnum, len) {
  var text = "";
  if (isnum) {
    var possible = "0123456789";
  } else {
    var possible =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  }
  for (var i = 0; i < len; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

function Scalar(name, id) {
  this.name = name;
  this.id = id;
  this.set = function (value, func, send_url) {
    var post_type = false && false ? ".php" : ".json";

    if (send_url == undefined) return;
    else send_url = "./data/" + send_url + post_type;

    //Invalid filter
    value = filterInvalidString(value);

    var in_data = this.id + "=" + encodeURIComponent(value);

    //page_data_send(send_url, in_data, func);
    //modify 20131016
    if (usermode == "") {
      //not login
      $.post(
        "./data/reset" +
          post_type +
          "?_=" +
          new Date().getTime() +
          "&csrf_token=" +
          csrf_token,
        "chk_sys_busy=" + encodeURIComponent(sys_username),
        function (data, textStatus, jqXHR) {
          if (data == "1") {
            window.parent.location = "fw_upgrade_progress.html";
          } else {
            page_data_send(send_url, in_data, func);
          }
        },
      );
    } else {
      if (name == "loginUserChkLoginTimeout") {
        page_data_send(send_url, in_data, func);
      } else {
        $.post(
          "./data/reset" +
            post_type +
            "?_=" +
            new Date().getTime() +
            "&csrf_token=" +
            csrf_token,
          "chk_sys_busy=" + encodeURIComponent(sys_username),
          function (data, textStatus, jqXHR) {
            if (data == "1") {
              window.parent.location = "fw_upgrade_progress.html";
            } else {
              loginUserChkLoginTimeout.set(
                sys_username,
                loginUserChkLoginTimeoutRet,
                "login",
              );
              page_data_send(send_url, in_data, func);
            }
          },
        );
      }
    }
    //add end

    return true;
  };
  this.set_sjcl = function (value, func, send_url) {
    var post_type = false && false ? ".php" : ".json";
    if (send_url == undefined) return;
    else send_url = "./data/" + send_url + post_type;

    //Invalid filter
    value = filterInvalidString(value);

    var in_data = this.id + "=" + encodeURIComponent(value);
    var in_reset_data = "chk_sys_busy=" + encodeURIComponent(sys_username);

    if (usermode == "") {
      //not login
      $.post(
        "./data/reset" +
          post_type +
          "?_=" +
          new Date().getTime() +
          "&csrf_token=" +
          csrf_token,
        in_reset_data,
        function (data, textStatus, jqXHR) {
          if (data == "1") {
            window.parent.location = "fw_upgrade_progress.html";
          } else {
            page_data_send(send_url, in_data, func);
          }
        },
      );
    } else {
      if (sys_sjcl_enable) {
        in_data = sjcl.encrypt(getWebStorage("dk"), in_data, {
          iter: 1000,
          iv: sjcl.random.randomWords(3, 0),
        });
        //in_reset_data = sjcl.encrypt(getWebStorage("dk"), in_reset_data, {iter:1000, iv:sjcl.random.randomWords(3,0)});
      }

      if (name == "loginUserChkLoginTimeout") {
        page_data_send(send_url, in_data, func);
      } else {
        $.post(
          "./data/reset" +
            post_type +
            "?_=" +
            new Date().getTime() +
            "&csrf_token=" +
            csrf_token,
          in_reset_data,
          function (data, textStatus, jqXHR) {
            if (data == "1") {
              window.parent.location = "fw_upgrade_progress.html";
            } else {
              //loginUserChkLoginTimeout.set_sjcl(sys_username, loginUserChkLoginTimeoutRet, 'login');
              loginUserChkLoginTimeout.set(
                sys_username,
                loginUserChkLoginTimeoutRet,
                "login",
              );
              page_data_send(send_url, in_data, func);
            }
          },
        );
      }
    }

    return true;
  };
}
//justin add 20140326
function filterInvalidString(data) {
  if (logMessage && window.console)
    console.log("filterInvalidString : " + typeof data);

  if (typeof data == "object") {
    data = replaceXssByJSON(data);
  } else if (typeof data == "string" && data.length >= 2) {
    var tmp_first = data.slice(0, 1);
    var tmp_last = data.slice(-1);
    if (
      (tmp_first == "[" && tmp_last == "]") ||
      (tmp_first == "{" && tmp_last == "}")
    ) {
      //JSON data
      var tmp_obj = jQuery.parseJSON(data);
      tmp_obj = replaceXssByJSON(tmp_obj);
      data = JSONToString(tmp_obj, tmp_first, tmp_last);
    } else {
      //string
      data = replaceXssByString(data);
    }
  } else if (typeof data == "string") {
    //string
    data = replaceXssByString(data);
  } else {
    //unknow
    data = replaceXssByString(data.toString());
  }

  return data;
}

function JSONToString(obj, first_s, last_s) {
  var data = first_s;
  var have_data = false;
  $.each(obj, function (key, val) {
    if (!have_data) have_data = true;

    if (typeof val == "object") {
      data += JSONToString(val, "{", "}") + ",";
    } else {
      data += '"' + key + '":"' + val + '",';
    }
  });

  if (have_data) data = data.slice(0, -1);
  data += last_s;

  return data;
}

function replaceXssByJSON(obj) {
  $.each(obj, function (key, val) {
    if (typeof val == "object") {
      replaceXssByJSON(val);
    } else {
      obj[key] = replaceXssByString(val.toString());
    }
  });

  return obj;
}

function replaceXssByString(data) {
  //filter &
  var testdata = data.toLowerCase();
  var rege1 = new RegExp("&lt");
  var rege2 = new RegExp("&gt");
  var rege3 = new RegExp("&#");
  while (rege1.test(testdata) || rege2.test(testdata) || rege3.test(testdata)) {
    if (logMessage && window.console) console.log("filterInvalidString!");

    testdata = testdata.replace("&", ""); //& amp;
    data = data.replace("&", ""); //& amp;
  }
  //filter other
  var rege = /[<>"'\\]/;
  while (rege.test(data)) {
    if (logMessage && window.console) console.log("filterInvalidString!");

    //data = data.replace('&', ''); //& amp;
    data = data.replace("<", ""); //& lt;
    data = data.replace(">", ""); //& gt;
    data = data.replace('"', ""); //& #34;
    data = data.replace("'", ""); //& #39;
    //data = data.replace("\/", ''); //& #47;
    data = data.replace("\\", ""); //& #92;
  }

  return data;
}
//justin add end

//justin add
var userDataPageId = new Scalar("userDataPageId", "pageid");
var userDataDropDownBasExp = new Scalar(
  "userDataDropDownBasExp",
  "dropDownBasExp",
);
var userDataLangCode = new Scalar("userDataLangCode", "lang_code");
var LoginName = new Scalar("LoginName", "LoginName");
var LoginPWD = new Scalar("LoginPWD", "LoginPWD");
var loginResetPassword = new Scalar("loginResetPassword", "loginResetPassword");
var loginUserResetToDefault = new Scalar(
  "loginUserResetToDefault",
  "loginUserResetToDefault",
);
var loginUserChkLoginTimeout = new Scalar(
  "loginUserChkLoginTimeout",
  "loginUserChkLoginTimeout",
);

var remoteAccessLoginName = new Scalar(
  "remoteAccessLoginName",
  "remoteAccessLoginName",
); //20131001
var remoteAccessLoginPassword = new Scalar(
  "remoteAccessLoginPassword",
  "remoteAccessLoginPassword",
);

var resetPages_reset_page = new Scalar("resetPages_reset_page", "reset_pages");

var overviewGetConnectionTrainingStatus = new Scalar(
  "overviewGetConnectionTrainingStatus",
  "GetConnectionTrainingStatus",
);
var overviewMSGDefaultConfiguration = new Scalar(
  "overviewMSGDefaultConfiguration",
  "MSGDefaultConfiguration",
);
var overviewMSGUMTSStickIsNotSupported = new Scalar(
  "overviewMSGUMTSStickIsNotSupported",
  "is_umts_stick_is_not_supported",
); //20151105
var overviewMSG_FW_Upgrade_Interrupted = new Scalar(
  "overviewMSG_FW_Upgrade_Interrupted",
  "is_fw_upgrade_interrupted",
); //20151130
var overviewMSGDefaultWIFI = new Scalar(
  "overviewMSGDefaultWIFI",
  "MSGDefaultWIFI",
);
var overviewMSGActivation = new Scalar(
  "overviewMSGActivation",
  "MSGActivation",
);
var overviewMSGExpertMode = new Scalar(
  "overviewMSGExpertMode",
  "MSGExpertMode",
);
var overviewMSGNeedNewWPS = new Scalar(
  "overviewMSGNeedNewWPS",
  "MSGNeedNewWPS",
);
var overviewMSGDefaultWPS = new Scalar(
  "overviewMSGDefaultWPS",
  "MSGDefaultWPS",
);

var GMSG_isn_umts = new Scalar("GMSG_isn_umts", "isn_umts");
var GMSG_voicemail_max_capacity = new Scalar(
  "GMSG_voicemail_max_capacity",
  "voicemail_max_capacity",
);
var GMSG_LTE_SIM_CARD = new Scalar("GMSG_LTE_SIM_CARD", "lte_pin_changed");
var GMSG_UMTS_SIM_CARD = new Scalar("GMSG_UMTS_SIM_CARD", "umts_pin_changed");
var GMSG_DifferentUser = new Scalar("GMSG_DifferentUser", "is_different_user");
var GMSG_WPS_Locked = new Scalar("GMSG_WPS_Locked", "wps_locked");
var GMSG_Default_WPS_PIN = new Scalar(
  "GMSG_Default_WPS_PIN",
  "is_default_wps_pin",
);
var GMSG_USB_is_not_supported = new Scalar(
  "GMSG_USB_is_not_supported",
  "is_usb_is_not_supported",
);
var GMSG_Validate_New_Email = new Scalar(
  "GMSG_Validate_New_Email",
  "validate_new_email",
);
var GMSG_Activate_Password = new Scalar(
  "GMSG_Activate_Password",
  "activate_password",
);
var GMSG_SIM_Is_Full = new Scalar("GMSG_SIM_Is_Full", "sim_is_full");
var GMSG_SMS_Is_Full = new Scalar("GMSG_SMS_Is_Full", "sms_is_full");

var phoneCallLogDeleteById = new Scalar(
  "phoneCallLogDeleteById",
  "CallLogDeleteById",
);
//var phoneCallLogDeleteAll = new Scalar("phoneCallLogDeleteAll", "CallLogDeleteAll"); //20130905
var phoneCallLogCallById = new Scalar(
  "phoneCallLogCallById",
  "CallLogCallById",
);
var phoneCallLogCallEnable = new Scalar(
  "phoneCallLogCallEnable",
  "CallLogCallEnable",
);
var phoneCallLogGetActiveStatusById = new Scalar(
  "phoneCallLogGetActiveStatusById",
  "CallLogGetActiveStatusById",
);

var phoneContactsDeleteById = new Scalar(
  "phoneContactsDeleteById",
  "ContactsDeleteById",
);
var phoneContactsEditData = new Scalar(
  "phoneContactsEditData",
  "ContactsEditData",
);
var phoneContactsAddData = new Scalar(
  "phoneContactsAddData",
  "ContactsAddData",
);
var phoneContactsFileDownload = new Scalar(
  "phoneContactsFileDownload",
  "ContactsFileDownload",
);

var phoneWakeUpCallEditData = new Scalar(
  "phoneWakeUpCallEditData",
  "WakeUpCallEditData",
);

var phoneRingingScheduleEditData = new Scalar(
  "phoneRingingScheduleEditData",
  "RingingScheduleEditData",
);

var internetPortMappingNATTraversal = new Scalar(
  "internetPortMappingNATTraversal",
  "nat_traversal",
); //20140417
var internetPortMappingEditData = new Scalar(
  "internetPortMappingEditData",
  "PortMappingEditData",
);
var internetPortMappingIsIPaddrError = new Scalar(
  "internetPortMappingIsIPaddrError",
  "PortMappingIsIPaddrError",
);
var internetPortMappingTriggerEditData = new Scalar(
  "internetPortMappingTriggerEditData",
  "PortMappingTriggerEditData",
);
var internetPortMappingALGsSIP = new Scalar(
  "internetPortMappingALGsSIP",
  "alg_sip",
);
var internetPortMappingALGsH323 = new Scalar(
  "internetPortMappingALGsH323",
  "alg_h323",
);
var internetPortMappingALGsFTP = new Scalar(
  "internetPortMappingALGsFTP",
  "alg_ftp",
);
var internetPortMappingALGsFTPPort = new Scalar(
  "internetPortMappingALGsFTPPort",
  "alg_ftp_port",
); //20140710
var internetPortMappingALGsL2TP = new Scalar(
  "internetPortMappingALGsL2TP",
  "alg_l2tp",
);
var internetPortMappingALGsPPTP = new Scalar(
  "internetPortMappingALGsPPTP",
  "alg_pptp",
);
var internetPortMappingALGsIPSE = new Scalar(
  "internetPortMappingALGsIPSE",
  "alg_ipse",
);

var internetDMZOnOff = new Scalar("internetDMZOnOff", "dmz_enable");
var internetDMZIPAddr = new Scalar("internetDMZIPAddr", "dmz_ip");
var internetCheckDMZIPAddr = new Scalar("internetCheckDMZIPAddr", "chk_dmz_ip"); //20131012

var internetStaticNATEnable = new Scalar(
  "internetStaticNATEnable",
  "static_nat_enable",
);
var internetStaticNATHost = new Scalar(
  "internetStaticNATHost",
  "static_nat_host",
);

var settingsPasswordUserData = new Scalar(
  "settingsPasswordUserData",
  "PasswordUserData",
);
var settingsPasswordPWD = new Scalar("settingsPasswordPWD", "pwd");
var settingsPasswordAutoLogout = new Scalar(
  "settingsPasswordAutoLogout",
  "auto_logout",
);
var settingsPasswordResetPWDByID = new Scalar(
  "settingsPasswordResetPWDByID",
  "reset_pwd_by_id",
); //20131203
var settingsPasswordValidation = new Scalar(
  "settingsPasswordValidation",
  "pwd_validation",
);
var settingsPasswordValidationAdmin = new Scalar(
  "settingsPasswordValidationAdmin",
  "pwd_validation_admin",
);

var settingsConfigurationSaveType = new Scalar(
  "settingsConfigurationSaveType",
  "ConfigurationSaveType",
);
var settingsConfigurationSaveDescription = new Scalar(
  "settingsConfigurationSaveDescription",
  "ConfigurationSaveDescription",
);
var settingsConfigurationSavePWD = new Scalar(
  "settingsConfigurationSavePWD",
  "ConfigurationSavePWD",
);
var settingsConfigurationRestore = new Scalar(
  "settingsConfigurationRestore",
  "ConfigurationRestore",
);
var settingsConfigurationRestorePWD = new Scalar(
  "settingsConfigurationRestorePWD",
  "ConfigurationRestorePWD",
);
var settingsConfigurationRestoreCheckbox = new Scalar(
  "settingsConfigurationRestoreCheckbox",
  "ConfigurationRestoreCheckbox",
);
var settingsConfigurationResetFactory = new Scalar(
  "settingsConfigurationResetFactory",
  "ConfigurationResetFactory",
); //new add
var settingsConfigurationRestoreType = new Scalar(
  "settingsConfigurationRestoreType",
  "ConfigurationRestoreType",
); //new add

var settingsFWUpdateInstallUpdateByUSB = new Scalar(
  "settingsFWUpdateInstallUpdateByUSB",
  "FWUpdateInstallUpdateByUSB",
);

var wifiWPSOnOff = new Scalar("wifiWPSOnOff", "wps_24g_onoff");
var wifiWPS5GOnOff = new Scalar("wifiWPS5GOnOff", "wps_5g_onoff");
var wifiWPS20Enable = new Scalar("wifiWPS20Enable", "wps20_enable"); //20131107 add
var wifiWPSAppliedTo = new Scalar("wifiWPSAppliedTo", "wps_applied_to");
var wifiWPSPBCEnable = new Scalar("wifiWPSPBCEnable", "wps_pbc_enable");

var wifiWPSPairToDeviceOnOff = new Scalar(
  "wifiWPSPairToDeviceOnOff",
  "WPSPairToDeviceOnOff",
);
var wifiWPSGetPairStatus = new Scalar(
  "wifiWPSGetPairStatus",
  "WPSGetPairStatus",
);
var wifiWPSPINNumber = new Scalar("wifiWPSPINNumber", "wps_pin_number"); //20140423
var wifiWPSPINPairOnOff = new Scalar(
  "wifiWPSPINPairOnOff",
  "wps_pin_pair_onoff",
); //20140423
var wifiWPSPINGetPairStatus = new Scalar(
  "wifiWPSPINGetPairStatus",
  "wps_pin_status",
); //20140423

var wifiPairingSmartApp = new Scalar(
  "wifiPairingSmartApp",
  "wifi_pairing_smart_app",
);

var wifiWDSOnOff = new Scalar("wifiWDSOnOff", "wifi_wdsonoff"); //20140113 add
var wifiWDSAPList = new Scalar("wifiWDSAPList", "wifi_wds_ap_list"); //20140113 add

var wifiGeneralNetworkOnOff = new Scalar(
  "wifiGeneralNetworkOnOff",
  "wifi_network_onoff",
);
var wifiGeneralSSID = new Scalar("wifiGeneralSSID", "wifi_ssid");
var wifiGeneralChannel = new Scalar("wifiGeneralChannel", "wifi_channel");
var wifiGeneralOBSS = new Scalar("wifiGeneralOBSS", "wifi_obss");
var wifiGeneralBroadcastSSID = new Scalar(
  "wifiGeneralBroadcastSSID",
  "wifi_broadcast_ssid",
);
var wifiGeneralProtection = new Scalar(
  "wifiGeneralProtection",
  "wifi_protection",
);
var wifiGeneralWEPModeLength = new Scalar(
  "wifiGeneralWEPModeLength",
  "wep_mode_length",
); //20130904 add
var wifiGeneralWEPModeEncrypt = new Scalar(
  "wifiGeneralWEPModeEncrypt",
  "wep_mode_encrypt",
); //20130904 add
var wifiGeneralWEPModeKey1 = new Scalar(
  "wifiGeneralWEPModeKey1",
  "wep_mode_key1",
); //20130904 add
var wifiGeneralWEPModeKey2 = new Scalar(
  "wifiGeneralWEPModeKey2",
  "wep_mode_key2",
); //20130904 add
var wifiGeneralWEPModeKey3 = new Scalar(
  "wifiGeneralWEPModeKey3",
  "wep_mode_key3",
); //20130904 add
var wifiGeneralWEPModeKey4 = new Scalar(
  "wifiGeneralWEPModeKey4",
  "wep_mode_key4",
); //20130904 add
var wifiGeneralWEPModeKeySelect = new Scalar(
  "wifiGeneralWEPModeKeySelect",
  "wep_mode_key_select",
); //20130904 add
var wifiGeneralWEPModeENPassphrase = new Scalar(
  "wifiGeneralWEPModeENPassphrase",
  "wep_mode_en_passphrase",
); //20130904 add
var wifiGeneralWEPModePassphrase = new Scalar(
  "wifiGeneralWEPModePassphrase",
  "wep_mode_passphrase",
); //20130904 add
var wifiGeneralPassword = new Scalar("wifiGeneralPassword", "wifi_password");
var wifiGeneralGenFrenquency = new Scalar(
  "wifiGeneralGenFrenquency",
  "wifi_genFrenquency",
); //admin
var wifiGeneralNumberOfWIFIDevices = new Scalar(
  "wifiGeneralNumberOfWIFIDevices",
  "wifi_number_of_wifi_devices",
); //admin

//20150508 add
var wifiGeneralNetworkOnOff_5G = new Scalar(
  "wifiGeneralNetworkOnOff_5G",
  "wifi_network_onoff_5g",
);
var wifiGeneralSSID_5G = new Scalar("wifiGeneralSSID_5G", "wifi_ssid_5g");
var wifiGeneralChannel_5G = new Scalar(
  "wifiGeneralChannel_5G",
  "wifi_channel_5g",
);
var wifiGeneralOBSS_5G = new Scalar("wifiGeneralOBSS_5G", "wifi_obss_5g");
var wifiGeneralBroadcastSSID_5G = new Scalar(
  "wifiGeneralBroadcastSSID_5G",
  "wifi_broadcast_ssid_5g",
);
var wifiGeneralProtection_5G = new Scalar(
  "wifiGeneralProtection_5G",
  "wifi_protection_5g",
);
var wifiGeneralWEPModeLength_5G = new Scalar(
  "wifiGeneralWEPModeLength_5G",
  "wep_mode_length_5g",
);
var wifiGeneralWEPModeKey1_5G = new Scalar(
  "wifiGeneralWEPModeKey1_5G",
  "wep_mode_key1_5g",
);
var wifiGeneralWEPModeKey2_5G = new Scalar(
  "wifiGeneralWEPModeKey2_5G",
  "wep_mode_key2_5g",
);
var wifiGeneralWEPModeKey3_5G = new Scalar(
  "wifiGeneralWEPModeKey3_5G",
  "wep_mode_key3_5g",
);
var wifiGeneralWEPModeKey4_5G = new Scalar(
  "wifiGeneralWEPModeKey4_5G",
  "wep_mode_key4_5g",
);
var wifiGeneralWEPModeKeySelect_5G = new Scalar(
  "wifiGeneralWEPModeKeySelect_5G",
  "wep_mode_key_select_5g",
);
var wifiGeneralWEPModePassphrase_5G = new Scalar(
  "wifiGeneralWEPModePassphrase_5G",
  "wep_mode_passphrase_5g",
);
var wifiGeneralPassword_5G = new Scalar(
  "wifiGeneralPassword_5G",
  "wifi_password_5g",
);
var wifiGeneralGenFrenquency_5G = new Scalar(
  "wifiGeneralGenFrenquency_5G",
  "wifi_genFrenquency_5g",
); //admin
var wifiGeneralNumberOfWIFIDevices_5G = new Scalar(
  "wifiGeneralNumberOfWIFIDevices_5G",
  "wifi_number_of_wifi_devices_5g",
); //admin
var wifiGeneralSplitSSID = new Scalar(
  "wifiGeneralSplitSSID",
  "split_ssid_enable",
);
//20150508 add end

var internetParentalControlEditData = new Scalar(
  "internetParentalControlEditData",
  "ParentalControlEditData",
);

var phoneSettingsSipPriRegistrarAddr = new Scalar(
  "phoneSettingsSipPriRegistrarAddr",
  "sip_pri_registrar_addr",
);
var phoneSettingsSipPriRegistrarPort = new Scalar(
  "phoneSettingsSipPriRegistrarPort",
  "sip_pri_registrar_port",
);
var phoneSettingsSipPriProxyServerAddr = new Scalar(
  "phoneSettingsSipPriProxyServerAddr",
  "sip_pri_proxy_server_addr",
);
var phoneSettingsSipPriProxyServerPort = new Scalar(
  "phoneSettingsSipPriProxyServerPort",
  "sip_pri_proxy_server_port",
);
var phoneSettingsSipPriOutboundProxy = new Scalar(
  "phoneSettingsSipPriOutboundProxy",
  "sip_pri_outbound_proxy",
);
var phoneSettingsSipPriOutboundPort = new Scalar(
  "phoneSettingsSipPriOutboundPort",
  "sip_pri_outbound_port",
);
var phoneSettingsSipSecRegistrarAddr = new Scalar(
  "phoneSettingsSipSecRegistrarAddr",
  "sip_sec_registrar_addr",
);
var phoneSettingsSipSecRegistrarPort = new Scalar(
  "phoneSettingsSipSecRegistrarPort",
  "sip_sec_registrar_port",
);
var phoneSettingsSipSecProxyServerAddr = new Scalar(
  "phoneSettingsSipSecProxyServerAddr",
  "sip_sec_proxy_server_addr",
);
var phoneSettingsSipSecProxyServerPort = new Scalar(
  "phoneSettingsSipSecProxyServerPort",
  "sip_sec_proxy_server_port",
);
var phoneSettingsSipSecOutboundProxy = new Scalar(
  "phoneSettingsSipSecOutboundProxy",
  "sip_sec_outbound_proxy",
);
var phoneSettingsSipSecOutboundPort = new Scalar(
  "phoneSettingsSipSecOutboundPort",
  "sip_sec_outbound_port",
);
var phoneSettingsUserAgentDomain = new Scalar(
  "phoneSettingsUserAgentDomain",
  "user_agent_domain",
);
var phoneSettingsExpirationDuration = new Scalar(
  "phoneSettingsExpirationDuration",
  "expiration_duration",
);
var phoneSettingsSessionExpires = new Scalar(
  "phoneSettingsSessionExpires",
  "session_expires",
);
var phoneSettingsOMCIProvision = new Scalar(
  "phoneSettingsOMCIProvision",
  "omci_provision",
);
var phoneSettingsUserAccountLine = new Scalar(
  "phoneSettingsUserAccountLine",
  "user_account_line",
); // 20131001
var phoneSettingsUserDisplayName = new Scalar(
  "phoneSettingsUserDisplayName",
  "user_display_name",
);
var phoneSettingsUserPhoneNumber = new Scalar(
  "phoneSettingsUserPhoneNumber",
  "user_phone_number",
);
var phoneSettingsUserName = new Scalar("phoneSettingsUserName", "user_name");
var phoneSettingsUserPassword = new Scalar(
  "phoneSettingsUserPassword",
  "user_password",
);
//add 20150514
var phoneSettingsUserAccountLine2 = new Scalar(
  "phoneSettingsUserAccountLine2",
  "user_account_line2",
);
var phoneSettingsUserDisplayName2 = new Scalar(
  "phoneSettingsUserDisplayName2",
  "user_display_name2",
);
var phoneSettingsUserPhoneNumber2 = new Scalar(
  "phoneSettingsUserPhoneNumber2",
  "user_phone_number2",
);
var phoneSettingsUserName2 = new Scalar("phoneSettingsUserName2", "user_name2");
var phoneSettingsUserPassword2 = new Scalar(
  "phoneSettingsUserPassword2",
  "user_password2",
);
//add end
var phoneSettingsVoiceDialPlanEnable = new Scalar(
  "phoneSettingsVoiceDialPlanEnable",
  "voicedialplan_enable",
);
var phoneSettingsVoipDialPlanSettings = new Scalar(
  "phoneSettingsVoipDialPlanSettings",
  "voip_dial_plan_settings",
);
var phoneSettingsVoipDialTimeout = new Scalar(
  "phoneSettingsVoipDialTimeout",
  "voip_dial_timeout",
);
var phoneSettingsFirstDigitTimeout = new Scalar(
  "phoneSettingsFirstDigitTimeout",
  "first_digit_timeout",
);
var phoneSettingsMinHookFlash = new Scalar(
  "phoneSettingsMinHookFlash",
  "min_hook_flash",
);
var phoneSettingsMaxHookFlash = new Scalar(
  "phoneSettingsMaxHookFlash",
  "max_hook_flash",
);

//var phoneSettingsPreferredTimeOption = new Scalar("phoneSettingsPreferredTimeOption", "preferred_time_option");
var phoneSettingsPreferredCodec1 = new Scalar(
  "phoneSettingsPreferredCodec1",
  "preferred_codec_1",
);
var phoneSettingsPreferredCodec2 = new Scalar(
  "phoneSettingsPreferredCodec2",
  "preferred_codec_2",
);
var phoneSettingsPreferredTimeOption1 = new Scalar(
  "phoneSettingsPreferredTimeOption1",
  "preferred_time_option_1",
); //20140515
//var phoneSettingsT38Codec1 = new Scalar("phoneSettingsT38Codec1", "t38_codec_1"); //20140515
var phoneSettingsPreferredTimeOption2 = new Scalar(
  "phoneSettingsPreferredTimeOption2",
  "preferred_time_option_2",
); //20140515
//var phoneSettingsT38Codec2 = new Scalar("phoneSettingsT38Codec2", "t38_codec_2"); //20140515
var phoneSettingsStateCodec1 = new Scalar(
  "phoneSettingsStateCodec1",
  "state_codec_1",
); //20140527
var phoneSettingsStateCodec2 = new Scalar(
  "phoneSettingsStateCodec2",
  "state_codec_2",
); //20140527
var phoneSettingsT38Codec = new Scalar("phoneSettingsT38Codec", "t38_codec");

var phoneSettingsVoiceReInjectionSettings = new Scalar(
  "phoneSettingsVoiceReInjectionSettings",
  "voice_re_injection_settings",
);
var phoneSettingsLocationSelect = new Scalar(
  "phoneSettingsLocationSelect",
  "location_select",
);
var phoneSettingsEchoCancellation = new Scalar(
  "phoneSettingsEchoCancellation",
  "echo_cancellation",
);
var phoneSettingsComfortNoise = new Scalar(
  "phoneSettingsComfortNoise",
  "comfort_noise",
);
var phoneSettingsVadSupport = new Scalar(
  "phoneSettingsVadSupport",
  "vad_support",
);
var phoneSettingsCngSupport = new Scalar(
  "phoneSettingsCngSupport",
  "cng_support",
); //20151029
var phoneSettingsSpeedDialingSupport = new Scalar(
  "phoneSettingsSpeedDialingSupport",
  "speed_dialing_support",
); //20151020
var phoneSettingsIngressGain = new Scalar(
  "phoneSettingsIngressGain",
  "ingress_gain",
);
var phoneSettingsEgressGain = new Scalar(
  "phoneSettingsEgressGain",
  "egress_gain",
);
var phoneSettingsFaxDetection = new Scalar(
  "phoneSettingsFaxDetection",
  "fax_detection",
);
var phoneSettingsDscpForRtp = new Scalar(
  "phoneSettingsDscpForRtp",
  "dscp_for_rtp",
);
var phoneSettingsSignallingDSCP = new Scalar(
  "phoneSettingsSignallingDSCP",
  "signalling_dscp",
);
var phoneSettingsLocalRtpMaxPort = new Scalar(
  "phoneSettingsLocalRtpMaxPort",
  "local_rtp_max_port",
);
var phoneSettingsLocalRtpMinPort = new Scalar(
  "phoneSettingsLocalRtpMinPort",
  "local_rtp_min_port",
);
var phoneSettingsRtcpPacketInterval = new Scalar(
  "phoneSettingsRtcpPacketInterval",
  "rtcp_packet_interval",
);
var phoneSettingsDtmfRelaySetting = new Scalar(
  "phoneSettingsDtmfRelaySetting",
  "dtmf_relay_setting",
);
var phoneSettingsDtmfPayloadValue = new Scalar(
  "phoneSettingsDtmfPayloadValue",
  "dtmf_payload_value",
);
var phoneSettingsRegistrationExpireTimeout = new Scalar(
  "phoneSettingsRegistrationExpireTimeout",
  "registration_expire_timeout",
);
var phoneSettingsRegistrationRetryInterval = new Scalar(
  "phoneSettingsRegistrationRetryInterval",
  "registration_retry_interval",
);
var phoneSettingsPrimaryProxyRetryInterval = new Scalar(
  "phoneSettingsPrimaryProxyRetryInterval",
  "primary_proxy_retry_interval",
);
var phoneSettingsSessionTimerExpires = new Scalar(
  "phoneSettingsSessionTimerExpires",
  "session_timer_expires",
);
var phoneSettingsSessionTimerMinSE = new Scalar(
  "phoneSettingsSessionTimerMinSE",
  "session_timer_min_se",
);
var phoneSettingsPrack = new Scalar("phoneSettingsPrack", "prack");
var phoneSettingsInterfaceName = new Scalar(
  "phoneSettingsInterfaceName",
  "interface_name",
); //20130815
var phoneSettingsregisterexpires = new Scalar(
  "phoneSettingsregisterexpires",
  "register_expires",
); //GPON201706
var phoneSettingsdeltaregistrationperiod = new Scalar(
  "phoneSettingsdeltaregistrationperiod",
  "delta_registration_period",
); //GPON201706
var phoneSettingsoutboundproxydhcp = new Scalar(
  "phoneSettingsoutboundproxydhcp",
  "outbound_proxy_dhcp",
); //GPON201706
var phoneSettingsw8021pmarkforrtp = new Scalar(
  "phoneSettingsw8021pmarkforrtp",
  "w8021p_mark_for_rtp",
); //GPON201706
var phoneSettingsw8021pmarkforsip = new Scalar(
  "phoneSettingsw8021pmarkforsip",
  "w8021p_mark_for_sip",
); //GPON201706
var phoneSettingsrtpteleventpayloadtype = new Scalar(
  "phoneSettingsrtpteleventpayloadtype",
  "rtp_televentpayloadtype",
); //GPON201706
var phoneSettingsjitterbuffermode = new Scalar(
  "phoneSettingsjitterbuffermode",
  "jitter_buffer_mode",
); //GPON201706
var phoneSettingsminjitterbuffer = new Scalar(
  "phoneSettingsminjitterbuffer",
  "min_jitter_buffer",
); //GPON201706
var phoneSettingsmaxjitterbuffer = new Scalar(
  "phoneSettingsmaxjitterbuffer",
  "max_jitter_buffer",
); //GPON201706
var phoneSettingscidtype = new Scalar("phoneSettingscidtype", "cid_type"); //GPON201706
var phoneSettingsdnssrv = new Scalar("phoneSettingsdnssrv", "dns_srv"); //GPON201706
var phoneSettingsimagedataredundancylevel = new Scalar(
  "phoneSettingsimagedataredundancylevel",
  "image_data_redundancy_level",
); //GPON201706
var phoneSettingst30dataredundancylevel = new Scalar(
  "phoneSettingst30dataredundancylevel",
  "t30_data_redundancy_level",
); //GPON201706

var phonePhoneNumbersTables = new Scalar(
  "phonePhoneNumbersTables",
  "phone_phone_numbers",
);
var phonePhoneConnectionsTables = new Scalar(
  "phonePhoneConnectionsTables",
  "phone_phone_connections",
);

var StatusAndSupportRestartDevice = new Scalar(
  "StatusAndSupportRestartDevice",
  "restart_device",
);
var StatusAndSupportRestartDSLReconnect = new Scalar(
  "StatusAndSupportRestartDSLReconnect",
  "dsl_reconnect",
);
var StatusAndSupportRestartFiberReconnect = new Scalar(
  "StatusAndSupportRestartFiberReconnect",
  "fiber_reconnect",
);

var StatusAndSupportEventLogDeleteAllLog = new Scalar(
  "StatusAndSupportEventLogDeleteAllLog",
  "delete_all_log",
);

var settingsAccessControlICMPWanSelect = new Scalar(
  "settingsAccessControlICMPWanSelect",
  "icmp_wan",
);
var settingsAccessControlICMPLanSelect = new Scalar(
  "settingsAccessControlICMPLanSelect",
  "icmp_lan",
);
var settingsAccessControlSNMPWanSelect = new Scalar(
  "settingsAccessControlSNMPWanSelect",
  "snmp_wan",
);
var settingsAccessControlSNMPLanSelect = new Scalar(
  "settingsAccessControlSNMPLanSelect",
  "snmp_lan",
);
var settingsAccessControlTelnetWanSelect = new Scalar(
  "settingsAccessControlTelnetWanSelect",
  "telnet_wan",
);
var settingsAccessControlTelnetLanSelect = new Scalar(
  "settingsAccessControlTelnetLanSelect",
  "telnet_lan",
);
var settingsAccessControlHTTPWanSelect = new Scalar(
  "settingsAccessControlHTTPWanSelect",
  "http_wan",
);
var settingsAccessControlHTTPLanSelect = new Scalar(
  "settingsAccessControlHTTPLanSelect",
  "http_lan",
);
var settingsAccessControlTR069WanSelect = new Scalar(
  "settingsAccessControlTR069WanSelect",
  "tr069_wan",
);
var settingsAccessControlTR069LanSelect = new Scalar(
  "settingsAccessControlTR069LanSelect",
  "tr069_lan",
);
var settingsAccessControlSSHWanSelect = new Scalar(
  "settingsAccessControlSSHWanSelect",
  "ssh_wan",
); //20140428
var settingsAccessControlSSHLanSelect = new Scalar(
  "settingsAccessControlSSHLanSelect",
  "ssh_lan",
); //20140428

var settingsxDSLSettingsVDSL8a = new Scalar(
  "settingsxDSLSettingsVDSL8a",
  "vdsl_8a",
); //new 20131129
var settingsxDSLSettingsVDSL8b = new Scalar(
  "settingsxDSLSettingsVDSL8b",
  "vdsl_8b",
); //new 20131129
var settingsxDSLSettingsVDSL8c = new Scalar(
  "settingsxDSLSettingsVDSL8c",
  "vdsl_8c",
); //new 20131129
var settingsxDSLSettingsVDSL8d = new Scalar(
  "settingsxDSLSettingsVDSL8d",
  "vdsl_8d",
); //new 20131129
var settingsxDSLSettingsVDSL12a = new Scalar(
  "settingsxDSLSettingsVDSL12a",
  "vdsl_12a",
); //new 20131129
var settingsxDSLSettingsVDSL12b = new Scalar(
  "settingsxDSLSettingsVDSL12b",
  "vdsl_12b",
); //new 20131204
var settingsxDSLSettingsVDSL17a = new Scalar(
  "settingsxDSLSettingsVDSL17a",
  "vdsl_17a",
); //new 20131129
var settingsxDSLSettingsVDSL30a = new Scalar(
  "settingsxDSLSettingsVDSL30a",
  "vdsl_30a",
); //new 20131129
var settingsxDSLSettingsVDSLUS0 = new Scalar(
  "settingsxDSLSettingsVDSLUS0",
  "vdsl_us0",
); //new 20131129

var settingsADSLSettingsGDmt = new Scalar("settingsADSLSettingsGDmt", "g_dmt"); //new 20130809
var settingsADSLSettingsGLite = new Scalar(
  "settingsADSLSettingsGLite",
  "g_lite",
); //new 20130809
var settingsADSLSettingsT1_413 = new Scalar(
  "settingsADSLSettingsT1_413",
  "t1_413",
); //new 20130809
var settingsADSLSettingsADSL2 = new Scalar(
  "settingsADSLSettingsADSL2",
  "adsl2",
); //new 20130809
var settingsADSLSettingsAnnexL = new Scalar(
  "settingsADSLSettingsAnnexL",
  "annexl",
); //new 20130809
var settingsADSLSettingsADSL2Plus = new Scalar(
  "settingsADSLSettingsADSL2Plus",
  "adsl2plus",
); //new 20130809
var settingsADSLSettingsAnnexM = new Scalar(
  "settingsADSLSettingsAnnexM",
  "annexm",
); //new 20130809
var settingsADSLSettingsBitswap = new Scalar(
  "settingsADSLSettingsBitswap",
  "bitswap",
);
var settingsADSLSettingsSRA = new Scalar("settingsADSLSettingsSRA", "sra"); //new 20130808

var wifiSettingsWIFIMode = new Scalar("wifiSettingsWIFIMode", "wifi-mode");
var wifiSettingsChannelSelect = new Scalar(
  "wifiSettingsChannelSelect",
  "channelSelect",
);
var wifiSettingsExtChannelSelect = new Scalar(
  "wifiSettingsExtChannelSelect",
  "extChannelSelect",
);
var wifiSettingsBandwidth = new Scalar("wifiSettingsBandwidth", "bandwidth");
var wifiSettingsPerodicAutoscan = new Scalar(
  "wifiSettingsPerodicAutoscan",
  "perodic_autoscan",
);
var wifiSettingsUpdateChannel = new Scalar(
  "wifiSettingsUpdateChannel",
  "update_channel",
);
var wifiSettingsSignalStrength = new Scalar(
  "wifiSettingsSignalStrength",
  "signalStrength",
);
var wifiSettingsEncryption = new Scalar(
  "wifiSettingsEncryption",
  "encrypthion",
);
var wifiSettingsKeyUpdateIntervall = new Scalar(
  "wifiSettingsKeyUpdateIntervall",
  "key_update_intervall",
);
//var wifiSettingsCTSMode = new Scalar("wifiSettingsCTSMode", "cts_mode");
//var wifiSettingsCTSType = new Scalar("wifiSettingsCTSType", "cts_type");
var wifiSettingsBeaconInterval = new Scalar(
  "wifiSettingsBeaconInterval",
  "beacon_interval",
);
var wifiSettingsDTIMInterval = new Scalar(
  "wifiSettingsDTIMInterval",
  "dtim_interval",
);
var wifiSettingsFragmentationTreshold = new Scalar(
  "wifiSettingsFragmentationTreshold",
  "fragmentation_treshold",
);
var wifiSettingsRTSTreshold = new Scalar(
  "wifiSettingsRTSTreshold",
  "rts_treshold",
);
var wifiSettingsWMMEnabled = new Scalar(
  "wifiSettingsWMMEnabled",
  "wmm_enabled",
);
var wifiSettingsAutoChannelReselection = new Scalar(
  "wifiSettingsAutoChannelReselection",
  "auto_channel_reselection",
);

//add 20150507
var wifiSettingsWIFIMode_5G = new Scalar(
  "wifiSettingsWIFIMode_5G",
  "wifi-mode_5g",
);
var wifiSettingsChannelSelect_5G = new Scalar(
  "wifiSettingsChannelSelect_5G",
  "channelSelect_5g",
);
var wifiSettingsExtChannelSelect_5G = new Scalar(
  "wifiSettingsExtChannelSelect_5G",
  "extChannelSelect_5g",
);
var wifiSettingsBandwidth_5G = new Scalar(
  "wifiSettingsBandwidth_5G",
  "bandwidth_5g",
);
var wifiSettingsPerodicAutoscan_5G = new Scalar(
  "wifiSettingsPerodicAutoscan_5G",
  "perodic_autoscan_5g",
);
var wifiSettingsUpdateChannel_5G = new Scalar(
  "wifiSettingsUpdateChannel_5G",
  "update_channel_5g",
);
var wifiSettingsSignalStrength_5G = new Scalar(
  "wifiSettingsSignalStrength_5G",
  "signalStrength_5g",
);
var wifiSettingsEncryption_5G = new Scalar(
  "wifiSettingsEncryption_5G",
  "encrypthion_5g",
);
var wifiSettingsKeyUpdateIntervall_5G = new Scalar(
  "wifiSettingsKeyUpdateIntervall_5G",
  "key_update_intervall_5g",
);
//var wifiSettingsCTSMode_5G = new Scalar("wifiSettingsCTSMode_5G", "cts_mode_5g");
//var wifiSettingsCTSType_5G = new Scalar("wifiSettingsCTSType_5G", "cts_type_5g");
var wifiSettingsBeaconInterval_5G = new Scalar(
  "wifiSettingsBeaconInterval_5G",
  "beacon_interval_5g",
);
var wifiSettingsDTIMInterval_5G = new Scalar(
  "wifiSettingsDTIMInterval_5G",
  "dtim_interval_5g",
);
var wifiSettingsFragmentationTreshold_5G = new Scalar(
  "wifiSettingsFragmentationTreshold_5G",
  "fragmentation_treshold_5g",
);
var wifiSettingsRTSTreshold_5G = new Scalar(
  "wifiSettingsRTSTreshold_5G",
  "rts_treshold_5g",
);
var wifiSettingsWMMEnabled_5G = new Scalar(
  "wifiSettingsWMMEnabled_5G",
  "wmm_enabled_5g",
);
var wifiSettingsAutoChannelReselection_5G = new Scalar(
  "wifiSettingsAutoChannelReselection_5G",
  "auto_channel_reselection_5g",
);
//add 20150507 end
var wifiSettingsDFSChannel_5G = new Scalar(
  "wifiSettingsDFSChannel_5G",
  "dfs_channel_5g",
);
var wifiAnalyserUpdateChannel = new Scalar(
  "wifiAnalyserUpdateChannel",
  "update_channel",
);

var phoneNoBlockingOutgoingNumberBlocking = new Scalar(
  "phoneNoBlockingOutgoingNumberBlocking",
  "outgoingNumberBlocking",
);
var phoneNoBlockingOutgoingNumberBlockingList = new Scalar(
  "phoneNoBlockingOutgoingNumberBlockingList",
  "outgoingNumberBlockingList",
);
var phoneNoBlockingIncomingNumberBlocking = new Scalar(
  "phoneNoBlockingIncomingNumberBlocking",
  "incomingNumberBlocking",
);
var phoneNoBlockingIncomingNumberBlockingList = new Scalar(
  "phoneNoBlockingIncomingNumberBlockingList",
  "incomingNumberBlockingList",
);
var phoneNoBlockingOutgoingBlockAllForeignNumbers = new Scalar(
  "phoneNoBlockingOutgoingBlockAllForeignNumbers",
  "outgoingBlockAllForeignNumbers",
);
var phoneNoBlockingOutgoingBlockAllSpecialRateNumbers = new Scalar(
  "phoneNoBlockingOutgoingBlockAllSpecialRateNumbers",
  "outgoingBlockAllSpecialRateNumbers",
);
var internetdyndnsSecureDNSEnable = new Scalar(
  "internetdyndnsSecureDNSEnable",
  "secure_dns_enable",
);
var internetdyndnsConfigureDNSEnable = new Scalar(
  "internetdyndnsConfigureDNSEnable",
  "configure_dns_enable",
);
var internetdyndnsDNS = new Scalar("internetdyndnsDNS", "dyndnsEnable");
var internetdyndnsProvider = new Scalar(
  "internetdyndnsProvider",
  "dyndnsProvider",
);
var internetdyndnsDomainName = new Scalar(
  "internetdyndnsDomainName",
  "dyndnsDomainName",
);
var internetdyndnsAccount = new Scalar(
  "internetdyndnsAccount",
  "dyndnsAccount",
);
var internetdyndnsPassword = new Scalar(
  "internetdyndnsPassword",
  "dyndnsPassword",
);

var internetdnsIP4PriDNSAddr = new Scalar(
  "internetdnsIP4PriDNSAddr",
  "ip4_pri_dns_addr",
);
var internetdnsIP4SecDNSAddr = new Scalar(
  "internetdnsIP4SecDNSAddr",
  "ip4_sec_dns_addr",
);
var internetdnsIP6PriDNSAddr = new Scalar(
  "internetdnsIP6PriDNSAddr",
  "ip6_pri_dns_addr",
);
var internetdnsIP6SecDNSAddr = new Scalar(
  "internetdnsIP6SecDNSAddr",
  "ip6_sec_dns_addr",
);

var internetFirewallFirewallContent = new Scalar(
  "internetFirewallFirewallContent",
  "firewallContent",
);
var internetFirewallFirewallAllowPing = new Scalar(
  "internetFirewallFirewallAllowPing",
  "firewallAllowPing",
);
var internetFirewallFirewallLevel = new Scalar(
  "internetFirewallFirewallLevel",
  "firewall_level",
);
var internetFirewallAllowPing = new Scalar(
  "internetFirewallAllowPing",
  "allow_ping",
);
var internetFirewallAttackAlertViaEmail = new Scalar(
  "internetFirewallAttackAlertViaEmail",
  "attackAlertViaEmail",
); //add 20131114
var internetFirewallEmailUsername = new Scalar(
  "internetFirewallEmailUsername",
  "email_username",
); //add 20131114
var internetFirewallEmailPassword = new Scalar(
  "internetFirewallEmailPassword",
  "email_password",
); //add 20131114
var internetFirewallEmailSMTPServ = new Scalar(
  "internetFirewallEmailSMTPServ",
  "email_smtp_serv",
); //add 20131114
var internetFirewallEmailSMTPPort = new Scalar(
  "internetFirewallEmailSMTPPort",
  "email_smtp_port",
); //add 20131114
var internetFirewallEmailTargetEmailAddr = new Scalar(
  "internetFirewallEmailTargetEmailAddr",
  "email_target_email_addr",
); //add 20131114
var internetFirewallTestEmail = new Scalar(
  "internetFirewallTestEmail",
  "test_email",
); //add 20131114
var internetFirewallDoS = new Scalar("internetFirewallDoS", "DoS");
var internetFirewallSystemICMP = new Scalar(
  "internetFirewallSystemICMP",
  "system_icmp",
);
var internetFirewallSystemICMPText = new Scalar(
  "internetFirewallSystemICMPText",
  "system_icmp_text",
);
var internetFirewallIpICMP = new Scalar("internetFirewallIpICMP", "ip_icmp");
var internetFirewallIpICMPText = new Scalar(
  "internetFirewallIpICMPText",
  "ip_icmp_text",
);
var internetFirewallSystemTCP = new Scalar(
  "internetFirewallSystemTCP",
  "system_tcp",
);
var internetFirewallSystemTCPText = new Scalar(
  "internetFirewallSystemTCPText",
  "system_tcp_text",
);
var internetFirewallIpTCP = new Scalar("internetFirewallIpTCP", "ip_tcp");
var internetFirewallIpTCPText = new Scalar(
  "internetFirewallIpTCPText",
  "ip_tcp_text",
);
var internetFirewallIpTCPFin = new Scalar(
  "internetFirewallIpTCPFin",
  "ip_tcp_fin",
);
var internetFirewallIpTCPFinText = new Scalar(
  "internetFirewallIpTCPFinText",
  "ip_tcp_fin_text",
);
var internetFirewallSystemUDP = new Scalar(
  "internetFirewallSystemUDP",
  "system_udp",
);
var internetFirewallSystemUDPText = new Scalar(
  "internetFirewallSystemUDPText",
  "system_udp_text",
);
var internetFirewallIpUDP = new Scalar("internetFirewallIpUDP", "ip_udp");
var internetFirewallIpUDPText = new Scalar(
  "internetFirewallIpUDPText",
  "ip_udp_text",
);
var internetFirewallSystemTCPFin = new Scalar(
  "internetFirewallSystemTCPFin",
  "system_tcp_fin",
);
var internetFirewallSystemTCPFinText = new Scalar(
  "internetFirewallSystemTCPFinText",
  "system_tcp_fin_text",
);
var internetFirewallICMPSmurf = new Scalar(
  "internetFirewallICMPSmurf",
  "icmp_smurf",
);
var internetFirewallIpFragmentation = new Scalar(
  "internetFirewallIpFragmentation",
  "ip_fragmentation",
);
var internetFirewallIpLand = new Scalar("internetFirewallIpLand", "ip_land");
var internetFirewallIPTearDrop = new Scalar(
  "internetFirewallIPTearDrop",
  "ip_tear_drop",
);
var internetFirewallPingOfDeath = new Scalar(
  "internetFirewallPingOfDeath",
  "ping_of_death",
);
var internetFirewallTCPScan = new Scalar("internetFirewallTCPScan", "tcp_scan");
var internetFirewallIpSpoof = new Scalar("internetFirewallIpSpoof", "ip_spoof");
var internetFirewallTCPUDPPortscan = new Scalar(
  "internetFirewallTCPUDPPortscan",
  "tcpudp_portscan",
);
var internetFirewallTCPSynwithdata = new Scalar(
  "internetFirewallTCPSynwithdata",
  "tcp_synwithdata",
);
var internetFirewallUDPBomb = new Scalar("internetFirewallUDPBomb", "udp_bomb");

var internetAccessControlListData = new Scalar(
  "internetAccessControlListData",
  "internet_access_control_list",
);

var internetIPv6FirewallTables = new Scalar(
  "internetIPv6FirewallTables",
  "internet_ipv6_firewall",
);
var internetIPv6FirewallDelIDList = new Scalar(
  "internetIPv6FirewallDelIDList",
  "del_id_list",
);
var internetIPv6FirewallEditIDList = new Scalar(
  "internetIPv6FirewallEditIDList",
  "edit_id_list",
);

var internetIPFilterDataList = new Scalar(
  "internetIPFilterDataList",
  "ip_filter_data_list",
);

var internetVPNSettingsData = new Scalar(
  "internetVPNSettingsData",
  "internet_vpn_settings_data",
);

var settingsWanSettingsEnable = new Scalar(
  "settingsWanSettingsEnable",
  "wan_settings_enable",
); //20130816
var settingsWanDeviceDrop = new Scalar("settingsWanDeviceDrop", "deviceDrop");
var settingsWanConnectionType = new Scalar(
  "settingsWanConnectionType",
  "connection_type",
);
var settingsWanConnectionStatus = new Scalar(
  "settingsWanConnectionStatus",
  "connection_status",
);
var settingsWanConnectionUsedFor = new Scalar(
  "settingsWanConnectionUsedFor",
  "connection_used_for",
);
var settingsWanNetworkAddrTranslation = new Scalar(
  "settingsWanNetworkAddrTranslation",
  "network_addr_translation",
); //new 20130808
var settingsWanFirewall = new Scalar("settingsWanFirewall", "firewall"); //new 20130808

var settingsWanDataList = new Scalar("settingsWanDataList", "wan_data_list"); //20140114
var settingsWanDelIDList = new Scalar("settingsWanDelIDList", "del_id_list"); //20140418
var settingsWanEditIDList = new Scalar("settingsWanEditIDList", "edit_id_list"); //20140418

var settingsWanATMVPI = new Scalar("settingsWanATMVPI", "atm_vpi"); //20131002
var settingsWanATMVCI = new Scalar("settingsWanATMVCI", "atm_vci"); //20131002
var settingsWanATMEncapsulationMode = new Scalar(
  "settingsWanATMEncapsulationMode",
  "atm_encapsulation_mode",
); //20131002
var settingsWanATMServiceCategory = new Scalar(
  "settingsWanATMServiceCategory",
  "atm_service_category",
); //20131002
var settingsWanATMPeakCellRate = new Scalar(
  "settingsWanATMPeakCellRate",
  "atm_peak_cell_rate",
); //20131002
var settingsWanATMSustainableCellRate = new Scalar(
  "settingsWanATMSustainableCellRate",
  "atm_sustainable_cell_rate",
); //20131002
var settingsWanATMMaximumBurstSize = new Scalar(
  "settingsWanATMMaximumBurstSize",
  "atm_maximum_burst_size",
); //20131002

var settingsWanVlanID = new Scalar("settingsWanVlanID", "vlan_id"); //20131008
var settingsWanVlan802dot1P = new Scalar(
  "settingsWanVlan802dot1P",
  "vlan_802dot1p",
); //20131008

var settingsWanPPPUsername = new Scalar(
  "settingsWanPPPUsername",
  "ppp_username",
);
var settingsWanPPPPassword = new Scalar(
  "settingsWanPPPPassword",
  "ppp_password",
);
var settingsWanPPPServiceName = new Scalar(
  "settingsWanPPPServiceName",
  "ppp_service_name",
);
var settingsWanPPPAuthenticationMethod = new Scalar(
  "settingsWanPPPAuthenticationMethod",
  "ppp_authentication_method",
);
var settingsWanPPPConnectionTrigger = new Scalar(
  "settingsWanPPPConnectionTrigger",
  "ppp_connection_trigger",
);
var settingsWanPPPLCPEchoRequestInterval = new Scalar(
  "settingsWanPPPLCPEchoRequestInterval",
  "ppp_lcp_echo_request_interval",
);
var settingsWanPPPMTU = new Scalar("settingsWanPPPMTU", "ppp_mtu"); //new 20130808
var settingsWanPPPIdleTime = new Scalar(
  "settingsWanPPPIdleTime",
  "ppp_idle_time",
); //new 20130816
var settingsWanPPPObtainDNSServers = new Scalar(
  "settingsWanPPPObtainDNSServers",
  "ppp_obtain_dns_servers",
);
var settingsWanPPPPrimaryDNS = new Scalar(
  "settingsWanPPPPrimaryDNS",
  "ppp_primary_dns",
); //new 20130808
var settingsWanPPPSecondaryDNS = new Scalar(
  "settingsWanPPPSecondaryDNS",
  "ppp_secondary_dns",
); //new 20130808
var settingsWanDHCPHostName = new Scalar(
  "settingsWanDHCPHostName",
  "dhcp_host_name",
); //new 20130808
var settingsWanDHCPMTU = new Scalar("settingsWanDHCPMTU", "dhcp_mtu"); //20131002
var settingsWanDHCPObtainDNSServers = new Scalar(
  "settingsWanDHCPObtainDNSServers",
  "dhcp_obtain_dns_servers",
); //new 20130808
var settingsWanDHCPPrimaryDNS = new Scalar(
  "settingsWanDHCPPrimaryDNS",
  "dhcp_primary_dns",
); //new 20130808
var settingsWanDHCPSecondaryDNS = new Scalar(
  "settingsWanDHCPSecondaryDNS",
  "dhcp_secondary_dns",
); //new 20130808
var settingsWanStaticHostName = new Scalar(
  "settingsWanStaticHostName",
  "static_host_name",
); //new 20130808
var settingsWanStaticIpAddr = new Scalar(
  "settingsWanStaticIpAddr",
  "static_ip_addr",
); //new 20130808
var settingsWanStaticNetmask = new Scalar(
  "settingsWanStaticNetmask",
  "static_netmask",
); //new 20130808
var settingsWanStaticGateway = new Scalar(
  "settingsWanStaticGateway",
  "static_gateway",
); //new 20130808
var settingsWanStaticMTU = new Scalar("settingsWanStaticMTU", "static_mtu"); //20131002
var settingsWanStaticObtainDNSServers = new Scalar(
  "settingsWanStaticObtainDNSServers",
  "static_obtain_dns_servers",
); //new 20130808
var settingsWanStaticPrimaryDNS = new Scalar(
  "settingsWanStaticPrimaryDNS",
  "static_primary_dns",
); //new 20130808
var settingsWanStaticSecondaryDNS = new Scalar(
  "settingsWanStaticSecondaryDNS",
  "static_secondary_dns",
); //new 20130808

var settingsStaticRoutingEditData = new Scalar(
  "settingsStaticRoutingEditData",
  "StaticRoutingEditData",
); // new 20130927

var settingsPolicyRoutingEditData = new Scalar(
  "settingsPolicyRoutingEditData",
  "PolicyRoutingEditData",
); //20140122
var settingsPolicyRoutingDelIDList = new Scalar(
  "settingsPolicyRoutingDelIDList",
  "del_id_list",
); //20140214
var settingsPolicyRoutingEditIDList = new Scalar(
  "settingsPolicyRoutingEditIDList",
  "edit_id_list",
); //20140214

var internetUPnPEnable = new Scalar("internetUPnPEnable", "upnp"); // new 20130927
var internetUPnPConfigurableEnable = new Scalar(
  "internetUPnPConfigurableEnable",
  "configurable",
); // new 20130927
var internetUPnPNATTraversalEnable = new Scalar(
  "internetUPnPNATTraversalEnable",
  "nat_raversal",
); // new 20130927

var internetWoLANEnable = new Scalar("internetWoLANEnable", "wolan");
var internetWoLANPublicPort = new Scalar(
  "internetWoLANPublicPort",
  "public_port",
);
var internetWoLANLanPort = new Scalar("internetWoLANLanPort", "lan_port");

var settingsTrustedNetworkEnable = new Scalar(
  "settingsTrustedNetworkEnable",
  "trusted_network",
); // new 20130930
var settingsTrustedNetworkList = new Scalar(
  "settingsTrustedNetworkList",
  "trusted_network_list",
); // new 20130930

var settingsContentSharingFolderDeviceID = new Scalar(
  "settingsContentSharingFolderDeviceID",
  "device_id",
); // new 20131019
var settingsContentSharingFolderPATH = new Scalar(
  "settingsContentSharingFolderPATH",
  "folder_path",
); // new 20131019

var settingsContentSharingUser = new Scalar(
  "settingsContentSharingUser",
  "sharing_user",
); // new 20131019
var settingsContentSharingUserADD = new Scalar(
  "settingsContentSharingUserADD",
  "sharing_user_add",
);
var settingsContentSharingUserEDIT = new Scalar(
  "settingsContentSharingUserEDIT",
  "sharing_user_edit",
);
var settingsContentSharingUserDEL = new Scalar(
  "settingsContentSharingUserDEL",
  "sharing_user_del",
);
var settingsContentSharingDevice = new Scalar(
  "settingsContentSharingDevice",
  "sharing_device",
); // new 20131019

var settingsContentSharingEnable = new Scalar(
  "settingsContentSharingEnable",
  "content_sharing_enable",
); // new 20131021

var settingsNetworkSharingEnable = new Scalar(
  "settingsNetworkSharingEnable",
  "network_sharing_enable",
); //20140414

var settingsPrinterSharingEnable = new Scalar(
  "settingsPrinterSharingEnable",
  "printer_sharing_enable",
); // new 20131021
var settingsPrinterSharingName = new Scalar(
  "settingsPrinterSharingName",
  "printer_name",
); //20140416
var settingsPrinterSharingServerURL = new Scalar(
  "settingsPrinterSharingServerURL",
  "printer_server_url",
); //20140416

var settingsUSBEjectID = new Scalar("settingsUSBEjectID", "eject_id"); // new 20131021

var settingsSNMPAgent = new Scalar("settingsSNMPAgent", "snmpagent"); // new 20131021
var settingsSNMPReadCommunity = new Scalar(
  "settingsSNMPReadCommunity",
  "snmp_read_community",
); // new 20131021
var settingsSNMPWriteCommunity = new Scalar(
  "settingsSNMPWriteCommunity",
  "snmp_write_community",
); // new 20131021
var settingsSNMPSystemName = new Scalar(
  "settingsSNMPSystemName",
  "snmp_system_name",
); // new 20131021
var settingsSNMPSystemLocation = new Scalar(
  "settingsSNMPSystemLocation",
  "snmp_system_location",
); // new 20131021
var settingsSNMPSystemContact = new Scalar(
  "settingsSNMPSystemContact",
  "snmp_system_contact",
); // new 20131021
var settingsSNMPSystemDescription = new Scalar(
  "settingsSNMPSystemDescription",
  "snmp_system_description",
); //20140121
var settingsSNMPUsername = new Scalar("settingsSNMPUsername", "snmp_username"); //20140414
var settingsSNMPAuthenticationProtocol = new Scalar(
  "settingsSNMPAuthenticationProtocol",
  "snmp_authentication_protocol",
); //20140414
var settingsSNMPAuthenticationKey = new Scalar(
  "settingsSNMPAuthenticationKey",
  "snmp_authentication_key",
); //20140414
var settingsSNMPPrivacyProtocol = new Scalar(
  "settingsSNMPPrivacyProtocol",
  "snmp_privacy_protocol",
); //20140414
var settingsSNMPPrivacyKey = new Scalar(
  "settingsSNMPPrivacyKey",
  "snmp_privacy_key",
); //20140414

var settingsQoS = new Scalar("settingsQoS", "qos_enable"); // new 20131022
var settingsQoSFTTHUpstreamBW = new Scalar(
  "settingsQoSFTTHUpstreamBW",
  "ftth_upstream_bw",
); //20140509
var settingsQoSRules = new Scalar("settingsQoSRules", "qos_rules"); // new 20131022
var settingsQoSDelIDList = new Scalar(
  "settingsQoSDelIDList",
  "qos_del_id_list",
); // new 20131213
var settingsQoSEditIDList = new Scalar(
  "settingsQoSEditIDList",
  "qos_edit_id_list",
); // new 20131213
var StatusAndSupportRunDiagnostic = new Scalar(
  "StatusAndSupportRunDiagnostic",
  "run_diagnostic",
); // new 20131022
var StatusAndSupportGetDiagnosticStatus = new Scalar(
  "StatusAndSupportGetDiagnosticStatus",
  "get_diagnostic_status",
); // new 20131022
var StatusAndSupportRunPing = new Scalar("StatusAndSupportRunPing", "run_ping");
var StatusAndSupportPingIPAddr = new Scalar(
  "StatusAndSupportPingIPAddr",
  "ip_addr",
);
var StatusAndSupportPingIP = new Scalar("StatusAndSupportPingIP", "ip");
var StatusAndSupportGetPingStatus = new Scalar(
  "StatusAndSupportGetPingStatus",
  "get_ping_status",
);
var StatusAndSupportRunTracing = new Scalar(
  "StatusAndSupportRunDiagnostic",
  "run_tracing",
);
var StatusAndSupportTracingConnectionType = new Scalar(
  "StatusAndSupportTracingConnectionType",
  "connection_type",
);
var StatusAndSupportGetTracingStatus = new Scalar(
  "StatusAndSupportGetDiagnosticStatus",
  "get_tracing_status",
);
var StatusAndSupportRunTraceRoute = new Scalar(
  "StatusAndSupportRunTraceRoute",
  "run_trace_route",
); // new 20171012
var StatusAndSupportGetTraceRouteStatus = new Scalar(
  "StatusAndSupportGetTraceRouteStatus",
  "get_trace_route_status",
); // new 20171012

var settingsDLNA = new Scalar("settingsDLNA", "settings_dlna"); // new 20131024
var settingsDLNAEnable = new Scalar("settingsDLNAEnable", "dlna_enable"); // new 20131024
var settingsDLNALanguage = new Scalar("settingsDLNALanguage", "dlna_language"); // new 20131024
var settingsDLNAFriendlyName = new Scalar(
  "settingsDLNAFriendlyName",
  "dlna_friendly_name",
); //20140612

var settingsFTPEnable = new Scalar("settingsFTPEnable", "ftp_enable"); //20140514
var settingsFTPShareViaInternetPort = new Scalar(
  "settingsFTPShareViaInternetPort",
  "ftp_share_via_internet_port",
); // new 20131024

var StatusAndSupportVOIPDiagnosticsSelectLogLevel = new Scalar(
  "StatusAndSupportVOIPDiagnosticsSelectLogLevel",
  "select_log_level",
); //new 20131025
var StatusAndSupportVOIPDiagnosticsDownload = new Scalar(
  "StatusAndSupportVOIPDiagnosticsDownload",
  "download",
); //new 20131025
var StatusAndSupportVOIPDiagnosticsTelephonyDiagnoseRing = new Scalar(
  "StatusAndSupportVOIPDiagnosticsTelephonyDiagnoseRing",
  "voip_tel_diagnose_ring",
); //new 20131212

var StatusAndSupportPacketTraceRunning = new Scalar(
  "StatusAndSupportPacketTraceRunning",
  "packet_trace_running",
);
var StatusAndSupportPacketTraceCaptureOnConnection = new Scalar(
  "StatusAndSupportPacketTraceCaptureOnConnection",
  "capture_on_connection",
);
var StatusAndSupportPacketTraceInput = new Scalar(
  "StatusAndSupportPacketTraceInput",
  "input",
);

var internetDSLAndUMTSReconnect = new Scalar(
  "internetDSLAndUMTSReconnect",
  "dsl_reconnect",
); //new 20131025
var internetDSLAndUMTSDetails = new Scalar(
  "internetDSLAndUMTSDetails",
  "umts_details",
); //add 20131107
var internetDSLAndUMTSBackupMode = new Scalar(
  "internetDSLAndUMTSBackupMode",
  "umts_backup_mode",
); //new 20131025
var internetDSLAndUMTSWirelessMode = new Scalar(
  "internetDSLAndUMTSWirelessMode",
  "umts_wireless_mode",
); //new 20131025
var internetDSLAndUMTSAPN = new Scalar("internetDSLAndUMTSAPN", "umts_apn"); //new 20131025
var internetDSLAndUMTSStick = new Scalar(
  "internetDSLAndUMTSStick",
  "umts_stick",
); //new 20131025
var internetDSLAndUMTSTimeUntilDisconnect = new Scalar(
  "internetDSLAndUMTSTimeUntilDisconnect",
  "umts_time_until_disconnect",
); //new 20131025
var internetDSLAndUMTSPINEnable = new Scalar(
  "internetDSLAndUMTSPINEnable",
  "umts_pin_enable",
); //add 20131107
var internetDSLAndUMTSPINCode = new Scalar(
  "internetDSLAndUMTSPINCode",
  "umts_pin_code",
); //add 20131107
var internetDSLAndUMTSSavePINCodeEnable = new Scalar(
  "internetDSLAndUMTSSavePINCodeEnable",
  "umts_save_pin_code",
); //20131206
var internetDSLAndUMTSResetPINCode = new Scalar(
  "internetDSLAndUMTSResetPINCode",
  "reset_pin_code",
); //add 20131107
var internetDSLAndUMTSPUKCode = new Scalar(
  "internetDSLAndUMTSPUKCode",
  "umts_puk_code",
); //20140120

var settingsUMTSBackup = new Scalar("settingsUMTSBackup", "backup"); // add 20131107
var settingsUMTSDisconnectionTimeout = new Scalar(
  "settingsUMTSDisconnectionTimeout",
  "disconnection_timeout",
); // 20140528
var settingsUMTSBackupMode = new Scalar(
  "settingsUMTSBackupMode",
  "backup_mode",
); // add 20131107
var settingsUMTSBackupModeDGW = new Scalar(
  "settingsUMTSBackupModeDGW",
  "backup_mode_dgw",
); // 20140528
var settingsUMTSBackupModeDNS = new Scalar(
  "settingsUMTSBackupModeDNS",
  "backup_mode_dns",
); // 20140528
var settingsUMTSDialNumber = new Scalar(
  "settingsUMTSDialNumber",
  "dial_number",
); // add 20131125
var settingsUMTS_PPPUsername = new Scalar(
  "settingsUMTS_PPPUsername",
  "ppp_username",
); // 20140528
var settingsUMTS_PPPPassword = new Scalar(
  "settingsUMTS_PPPPassword",
  "ppp_pwd",
); // 20140528
var settingsUMTSIdleTime = new Scalar("settingsUMTSIdleTime", "idle_time"); // 20140528
var settingsUMTSVoiceOverPSBackup = new Scalar(
  "settingsUMTSVoiceOverPSBackup",
  "voice_over_ps_backup",
); // add 20131125
var settingsUMTSVoiceOverPSBackupMode = new Scalar(
  "settingsUMTSVoiceOverPSBackupMode",
  "voice_over_ps_backup_mode",
); //20140417
var settingsUMTSAPNData = new Scalar("settingsUMTSAPNData", "apn_data"); // add 20131107
var settingsUMTSNetworkSelection = new Scalar(
  "settingsUMTSNetworkSelection",
  "network_selection",
); // add 20131107
var settingsUMTSNetworkGeneration = new Scalar(
  "settingsUMTSNetworkGeneration",
  "network_generation",
); // 20140528
var settingsUMTSNetworkOperator = new Scalar(
  "settingsUMTSNetworkOperator",
  "network_operator",
); // add 20131107
var settingsUMTSICMPCheckTimer = new Scalar(
  "settingsUMTSICMPCheckTimer",
  "icmp_check_timer",
); // add 20131107
var settingsUMTSDNSLookupTimer = new Scalar(
  "settingsUMTSDNSLookupTimer",
  "dns_lookup_timer",
); // add 20131107
var settingsUMTSDelayBeforeSwitchingVoiceFromWANtoHSPA = new Scalar(
  "settingsUMTSDelayBeforeSwitchingVoiceFromWANtoHSPA",
  "delay_before_switching_voice_from_wan_to_hspa",
); // add 20131107
var settingsUMTSDelayBeforeSwitchingVoiceFromHSPAtoWAN = new Scalar(
  "settingsUMTSDelayBeforeSwitchingVoiceFromHSPAtoWAN",
  "delay_before_switching_voice_from_hspa_to_wan",
); // add 20131107
var settingsUMTSDelayBeforeSwitchingDataFromWANtoHSPA = new Scalar(
  "settingsUMTSDelayBeforeSwitchingDataFromWANtoHSPA",
  "delay_before_switching_data_from_wan_to_hspa",
); // add 20131125
var settingsUMTSDelayBeforeSwitchingDataFromHSPAtoWAN = new Scalar(
  "settingsUMTSDelayBeforeSwitchingDataFromHSPAtoWAN",
  "delay_before_switching_data_from_hspa_to_wan",
); // add 20131125

var settingsIPv6BasicConfigurationIPv6Enable = new Scalar(
  "settingsIPv6BasicConfigurationIPv6Enable",
  "ipv6_enable",
);
var settingsIPv6BasicConfigurationIPv6ClientRapidCommit = new Scalar(
  "settingsIPv6BasicConfigurationIPv6ClientRapidCommit",
  "ipv6client_rapid_commit",
);
var settingsIPv6BasicConfigurationIPv6ClientIA_PD = new Scalar(
  "settingsIPv6BasicConfigurationIPv6ClientIA_PD",
  "ipv6client_ia_pd",
);
var settingsIPv6BasicConfigurationIPv6Client_IA_PD_PrefixMode = new Scalar(
  "settingsIPv6BasicConfigurationIPv6Client_IA_PD_PrefixMode",
  "ipv6client_ia_pd_prefix_mode",
);
var settingsIPv6BasicConfigurationIPv6Client_IA_PD_PrefixModeSelect =
  new Scalar(
    "settingsIPv6BasicConfigurationIPv6Client_IA_PD_PrefixModeSelect",
    "ipv6client_ia_pd_prefix_mode_select",
  );
var settingsIPv6BasicConfigurationIPv6Client_IA_PD_PrefixModeFromTimerBased =
  new Scalar(
    "settingsIPv6BasicConfigurationIPv6Client_IA_PD_PrefixModeFromTimerBased",
    "ipv6client_ia_pd_prefix_mode_from_timer_based",
  ); //20140508
var settingsIPv6BasicConfigurationIPv6Client_IA_PD_PrefixModeToTimerBased =
  new Scalar(
    "settingsIPv6BasicConfigurationIPv6Client_IA_PD_PrefixModeToTimerBased",
    "ipv6client_ia_pd_prefix_mode_to_timer_based",
  ); //20140508
var settingsIPv6BasicConfigurationIPv6ClientDNS = new Scalar(
  "settingsIPv6BasicConfigurationIPv6ClientDNS",
  "ipv6client_dns",
);
var settingsIPv6BasicConfigurationIPv6Server_IA_NA = new Scalar(
  "settingsIPv6BasicConfigurationIPv6Server_IA_NA",
  "ipv6server_ia_na",
);
var settingsIPv6BasicConfigurationIPv6ServerDNS = new Scalar(
  "settingsIPv6BasicConfigurationIPv6ServerDNS",
  "ipv6server_dns",
);
var settingsIPv6BasicConfigurationAdvManagedFlag = new Scalar(
  "settingsIPv6BasicConfigurationAdvManagedFlag",
  "adv_managed_flag",
);
var settingsIPv6BasicConfigurationAdvOtherConfigFlag = new Scalar(
  "settingsIPv6BasicConfigurationAdvOtherConfigFlag",
  "adv_other_config_flag",
);
var settingsIPv6BasicConfigurationAdvDefaultLifetime = new Scalar(
  "settingsIPv6BasicConfigurationAdvDefaultLifetime",
  "adv_default_lifetime",
);
var settingsIPv6BasicConfigurationAdvLinkMTU = new Scalar(
  "settingsIPv6BasicConfigurationAdvLinkMTU",
  "adv_link_mtu",
);
var settingsIPv6BasicConfigurationMaxRtrAdvInterval = new Scalar(
  "settingsIPv6BasicConfigurationMaxRtrAdvInterval",
  "max_rtr_adv_interval",
);
var settingsIPv6BasicConfigurationMinRtrAdvInterval = new Scalar(
  "settingsIPv6BasicConfigurationMinRtrAdvInterval",
  "min_rtr_adv_interval",
);
var settingsIPv6BasicConfigurationAdvPreferredLifetime = new Scalar(
  "settingsIPv6BasicConfigurationAdvPreferredLifetime",
  "adv_preferred_lifetime",
);
var settingsIPv6BasicConfigurationAdvValidLifetime = new Scalar(
  "settingsIPv6BasicConfigurationAdvValidLifetime",
  "adv_valid_lifetime",
);

var settingsIPv6BasicConfigurationIA_PD_PrefixModeRenew = new Scalar(
  "settingsIPv6BasicConfigurationIA_PD_PrefixModeRenew",
  "ia_pd_prefix_mode_renew",
);

var settingsTVsettings_Redirections = new Scalar(
  "settingsTVsettings_Redirections",
  "redirections",
); //20150316
var settingsTVsettings_DHCPStartIP = new Scalar(
  "settingsTVsettings_DHCPStartIP",
  "dhcp_start_ip",
); //20150316
var settingsTVsettings_DHCPEndIP = new Scalar(
  "settingsTVsettings_DHCPEndIP",
  "dhcp_end_ip",
); //20150316
var settingsTVsettings_DHCPStbOption12 = new Scalar(
  "settingsTVsettings_DHCPStbOption12",
  "dhcp_stb_option12",
); //20150316
var settingsTVsettings_IsIPaddrError = new Scalar(
  "settingsTVsettings_IsIPaddrError",
  "is_ipaddr_error",
); //20150316

var settingsEnergysettings_LEDStatus = new Scalar(
  "settingsEnergysettings_LEDStatus",
  "led_status",
); //20150603
var settingsEnergysettings_USBPort = new Scalar(
  "settingsEnergysettings_USBPort",
  "usb_port",
);
var settingsEnergysettings_LEDPower = new Scalar(
  "settingsEnergysettings_LEDPower",
  "led_power",
); //20150603
var settingsEnergysettings_LEDPowerBrightness = new Scalar(
  "settingsEnergysettings_LEDPowerBrightness",
  "led_power_brightness",
); //20150603
var settingsEnergysettings_CPUPowerSavingStatus = new Scalar(
  "settingsEnergysettings_CPUPowerSavingStatus",
  "cpu_power_saving_status",
);

var StatusAndSupportPortMirroringStart = new Scalar(
  "StatusAndSupportPortMirroringStart",
  "port_mirroring_start",
); //20140430
var StatusAndSupportPortMirroringStop = new Scalar(
  "StatusAndSupportPortMirroringStop",
  "port_mirroring_stop",
); //20140430

var wifiVFWiFiEnable = new Scalar("wifiVFWiFiEnable", "vodafone_wifi_enable"); //20150303
var wifiVFWiFiUserSelectableEnable = new Scalar(
  "wifiVFWiFiUserSelectableEnable",
  "user_selectable_enable",
); //20150303
var wifiVFWiFiSoftGREServer = new Scalar(
  "wifiVFWiFiSoftGREServer",
  "softgre_server",
); //20150303
var wifiVFWiFiSoftGREEapServer = new Scalar(
  "wifiVFWiFiSoftGREEapServer",
  "softgre_eap_server",
); //20150303
var wifiVFWiFiAuthPort = new Scalar("wifiVFWiFiAuthPort", "auth_port"); //20150303
var wifiVFWiFiAccountingPort = new Scalar(
  "wifiVFWiFiAccountingPort",
  "accounting_port",
); //20150303
var wifiVFWiFiVlanOpenSSID = new Scalar(
  "wifiVFWiFiVlanOpenSSID",
  "vlan_openssid",
); //20150303
var wifiVFWiFiVlanEapSSID = new Scalar("wifiVFWiFiVlanEapSSID", "vlan_eapssid"); //20150303
var wifiVFWiFiEapSecret = new Scalar("wifiVFWiFiEapSecret", "eap_secret"); //20150303
var wifiVFWiFiQOSMaxAssocUsers = new Scalar(
  "wifiVFWiFiQOSMaxAssocUsers",
  "qos_max_assoc_users",
); //20150303
var wifiVFWiFiQOSMaxAssocUsersOpenSSID = new Scalar(
  "wifiVFWiFiQOSMaxAssocUsersOpenSSID",
  "qos_max_assoc_users_openssid",
); //20150303
var wifiVFWiFiQOSMaxAssocUsersEapSSID = new Scalar(
  "wifiVFWiFiQOSMaxAssocUsersEapSSID",
  "qos_max_assoc_users_eapssid",
); //20150303
var wifiVFWiFiQOSMinimumSyncSpeed = new Scalar(
  "wifiVFWiFiQOSMinimumSyncSpeed",
  "qos_minimum_sync_speed",
); //20150303
var wifiVFWiFiQOSPercentBW = new Scalar(
  "wifiVFWiFiQOSPercentBW",
  "qos_percent_bw",
); //20150303
var wifiVFWiFiQOSMaxBW = new Scalar("wifiVFWiFiQOSMaxBW", "qos_max_bw"); //20150303
var wifiVFWiFiQOSPercentBWRadio = new Scalar(
  "wifiVFWiFiQOSPercentBWRadio",
  "qos_percent_bw_radio",
); //20150303
var wifiVFWiFiQOSMaxBWRadio = new Scalar(
  "wifiVFWiFiQOSMaxBWRadio",
  "qos_max_bw_radio",
); //20150303

var sharing_sharing_device_id = new Scalar(
  "sharing_sharing_device_id",
  "deivce_id",
);
var sharing_sharing_delete_file = new Scalar(
  "sharing_sharing_delete_file",
  "delete_file",
);
var sharing_sharing_download_file = new Scalar(
  "sharing_sharing_download_file",
  "download_file",
);

var sharing_settings_eject_device_id = new Scalar(
  "sharing_settings_eject_device_id",
  "eject_device_id",
);
var sharing_settings = new Scalar("sharing_settings", "sharing_settings");

var wifiBandSteeringEnable = new Scalar(
  "wifiBandSteeringEnable",
  "band_steering",
);
var wifiBandSteeringMacEnable = new Scalar(
  "wifiBandSteeringMacEnable",
  "exclude_from_band_steering",
);
var wifiBandSteeringMacList = new Scalar("wifiBandSteeringMacList", "mac_list");
//justin add end
var wifiSuperWifiEnable = new Scalar(
  "wifiSuperWifiEnable",
  "super_wifi_enable",
);
var wifiSuperWifiMode = new Scalar("wifiSuperWifiMode", "super_wifi_mode");

//luis add
var settingsLanIP = new Scalar("settingsLanIP", "LanIP");
var settingsLanSubnetMask = new Scalar(
  "settingsLanSubnetMask",
  "LanSubnetMask",
);
var settingsLanHostName = new Scalar("settingsLanHostName", "LanHostName");
var settingsLanDNSServer = new Scalar("settingsLanDNSServer", "LanDNSServer"); //20130909
var settingsLanDNSProxy = new Scalar("settingsLanDNSProxy", "LanDNSProxy"); //20130909
var settingsLanDHCP = new Scalar("settingsLanDHCP", "LanDHCP");
var settingsLanDHCPStartIP = new Scalar(
  "settingsLanDHCPStartIP",
  "LanDHCPStartIP",
);
var settingsLanDHCPEndIP = new Scalar("settingsLanDHCPEndIP", "LanDHCPEndIP");
var settingsLanLeaseTime = new Scalar(
  "settingsLanDHCPLeaseTime",
  "LanDHCPLeaseTime",
);
var settingsLanDomainName = new Scalar(
  "settingsLanDHCPDomainName",
  "LanDHCPDomainName",
);
var settingsLanDHCPOption66 = new Scalar(
  "settingsLanDHCPOption66",
  "LanDHCPOption66",
); //20140526
var settingsLanDHCPOption67 = new Scalar(
  "settingsLanDHCPOption67",
  "LanDHCPOption67",
); //20140526
var settingsLanDHCPOption160 = new Scalar(
  "settingsLanDHCPOption160",
  "LanDHCPOption160",
); //20140526
var settingsLanStaticDHCPList = new Scalar(
  "settingsLanStaticDHCPList",
  "LanStaticDHCPList",
);
var settingsLanIPv6DHCPServer = new Scalar(
  "settingsLanIPv6DHCPServer",
  "ip6_dhcp_server",
); //20140429
var settingsLanIPv6RouterAdvertisement = new Scalar(
  "settingsLanIPv6RouterAdvertisement",
  "ip6_router_advertisement",
); //20140429
var settingsLanIP_GUEST = new Scalar("settingsLanIP_GUEST", "LanIP_guest");
var settingsLanSubnetMask_GUEST = new Scalar(
  "settingsLanSubnetMask_GUEST",
  "LanSubnetMask_guest",
);
var settingsLanSubnetMask_GUEST = new Scalar(
  "settingsLanSubnetMask_GUEST",
  "LanSubnetMask_guest",
);
var settingsLanDHCP_GUEST = new Scalar(
  "settingsLanDHCP_GUEST",
  "LanDHCP_guest",
);
var settingsLanDHCPStartIP_GUEST = new Scalar(
  "settingsLanDHCPStartIP_GUEST",
  "LanDHCPStartIP_guest",
);
var settingsLanDHCPEndIP_GUEST = new Scalar(
  "settingsLanDHCPEndIP_GUEST",
  "LanDHCPEndIP_guest",
);
var settingsLanLeaseTime_GUEST = new Scalar(
  "settingsLanLeaseTime_GUEST",
  "LanDHCPLeaseTime_guest",
);
var settingsLanDomainName_GUEST = new Scalar(
  "settingsLanDomainName_GUEST",
  "LanDHCPDomainName_guest",
);
var settingsLanStaticDHCPList_GUEST = new Scalar(
  "settingsLanStaticDHCPList_GUEST",
  "LanStaticDHCPList_guest",
);

var settingsLanSubnet = new Scalar("settingsLanSubnet", "subnet"); //20140429

var wifiScheduleFunction = new Scalar(
  "wifiScheduleFunction",
  "ScheduleFunction",
);
var wifiScheduleAllowwifi = new Scalar(
  "wifiScheduleAllowwifi",
  "ScheduleAllowwifi",
);
var wifiScheduleList = new Scalar("wifiScheduleList", "ScheduleList");

var internetdyndnsEDNSEnable = new Scalar(
  "internetdyndnsEDNSEnable",
  "edns0_enable",
); // peter 09/18 '18
var internetdyndnsSecureDNSEnable = new Scalar(
  "internetdyndnsSecureDNSEnable",
  "secure_dns_enable",
);
var internetdyndnsDNS = new Scalar("internetdyndnsDNS", "dyndnsEnable");
var internetdyndnsProvider = new Scalar(
  "internetdyndnsProvider",
  "dyndnsProvider",
);
var internetdyndnsDomainName = new Scalar(
  "internetdyndnsDomainName",
  "dyndnsDomainName",
);
var internetdyndnsAccount = new Scalar(
  "internetdyndnsAccount",
  "dyndnsAccount",
);
var internetdyndnsPassword = new Scalar(
  "internetdyndnsPassword",
  "dyndnsPassword",
);
var phonePhoneConnectionsTables = new Scalar(
  "phonePhoneConnectionsTables",
  "phone_phone_connections",
);
var phonePhoneSettingsTables = new Scalar(
  "phonePhoneSettingsTables",
  "phone_phone_settings",
);
//var phonecallsettingdisplaycallnumber = new Scalar("phonecallsettingdisplaycallnumber", "callsetting_display_call_number");
//var phonecallsettingsendphonenumber = new Scalar("phonecallsettingsendphonenumber", "callsetting_send_phone_number");
var phonecallsettingcallhold = new Scalar(
  "phonecallsettingcallhold",
  "callsetting_call_hold",
);
var phonecallsettingcallwaiting = new Scalar(
  "phonecallsettingcallwaiting",
  "callsetting_call_waiting",
);
var phonecallsettingthreewaycalling = new Scalar(
  "phonecallsettingthreewaycalling",
  "callsetting_three_way_calling",
);
var phonecallsettingcalltransfer = new Scalar(
  "phonecallsettingcalltransfer",
  "callsetting_call_transfer",
);
var phonecallsettingautomaticcall = new Scalar(
  "phonecallsettingautomaticcall",
  "callsetting_automatic_call",
);
var phonecallsettingautomaticcallnumber = new Scalar(
  "phonecallsettingautomaticcallnumber",
  "callsetting_automatic_call_number",
);
var phonecallsettingautomaticcalltimeout = new Scalar(
  "phonecallsettingautomaticcalltimeout",
  "callsetting_automatic_call_timeout",
);
//var phonecallsettingmwi = new Scalar("phonecallsettingmwi", "callsetting_mwi");
//var phonecallsettingdisplaycallnumber_prov = new Scalar("phonecallsettingdisplaycallnumber_prov", "callsetting_display_call_number_prov");
//var phonecallsettingsendphonenumber_prov = new Scalar("phonecallsettingsendphonenumber_prov", "callsetting_send_phone_number_prov");
var phonecallsettingcallhold_prov = new Scalar(
  "phonecallsettingcallhold_prov",
  "callsetting_call_hold_prov",
);
var phonecallsettingcallwaiting_prov = new Scalar(
  "phonecallsettingcallwaiting_prov",
  "callsetting_call_waiting_prov",
);
var phonecallsettingthreewaycalling_prov = new Scalar(
  "phonecallsettingthreewaycalling_prov",
  "callsetting_three_way_calling_prov",
);
var phonecallsettingcalltransfer_prov = new Scalar(
  "phonecallsettingcalltransfer_prov",
  "callsetting_call_transfer_prov",
);
var phonecallsettingautomaticcall_prov = new Scalar(
  "phonecallsettingautomaticcall_prov",
  "callsetting_automatic_call_prov",
);
//var phonecallsettingmwi_prov = new Scalar("phonecallsettingmwi_prov", "callsetting_mwi_prov");
//20150214 add
var phonecallsettingcallhold2 = new Scalar(
  "phonecallsettingcallhold2",
  "callsetting_call_hold2",
);
var phonecallsettingcallwaiting2 = new Scalar(
  "phonecallsettingcallwaiting2",
  "callsetting_call_waiting2",
);
var phonecallsettingthreewaycalling2 = new Scalar(
  "phonecallsettingthreewaycalling2",
  "callsetting_three_way_calling2",
);
var phonecallsettingcalltransfer2 = new Scalar(
  "phonecallsettingcalltransfer2",
  "callsetting_call_transfer2",
);
var phonecallsettingautomaticcall2 = new Scalar(
  "phonecallsettingautomaticcall2",
  "callsetting_automatic_call2",
);
var phonecallsettingautomaticcallnumber2 = new Scalar(
  "phonecallsettingautomaticcallnumber2",
  "callsetting_automatic_call_number2",
);
var phonecallsettingautomaticcalltimeout2 = new Scalar(
  "phonecallsettingautomaticcalltimeout2",
  "callsetting_automatic_call_timeout2",
);
var phonecallsettingcallhold_prov2 = new Scalar(
  "phonecallsettingcallhold_prov2",
  "callsetting_call_hold_prov2",
);
var phonecallsettingcallwaiting_prov2 = new Scalar(
  "phonecallsettingcallwaiting_prov2",
  "callsetting_call_waiting_prov2",
);
var phonecallsettingthreewaycalling_prov2 = new Scalar(
  "phonecallsettingthreewaycalling_prov2",
  "callsetting_three_way_calling_prov2",
);
var phonecallsettingcalltransfer_prov2 = new Scalar(
  "phonecallsettingcalltransfer_prov2",
  "callsetting_call_transfer_prov2",
);
var phonecallsettingautomaticcall_prov2 = new Scalar(
  "phonecallsettingautomaticcall_prov2",
  "callsetting_automatic_call_prov2",
);
//20150214 add end

var wifimacFilterFiltering = new Scalar(
  "wifimacFilterFiltering",
  "macFilterFiltering",
);
var wifimacFilterAccessListed = new Scalar(
  "wifimacFilterAccessListed",
  "access_listed",
);
var wifimacFilterList = new Scalar("wifimacFilterList", "macFilterList");

var wifimacFilterFilteringGuest = new Scalar(
  "wifimacFilterFilteringGuest",
  "mac_filtering_guest",
);
var wifimacFilterAccessListedGuest = new Scalar(
  "wifimacFilterAccessListedGuest",
  "access_listed_guest",
);
var wifimacFilterListGuest = new Scalar(
  "wifimacFilterListGuest",
  "macFilterList_guest",
);

var wifiexcludeDeviceList = new Scalar(
  "wifiexcludeDeviceList",
  "excludeDeviceList",
); //20190515

var statusSupport_adsl_reset = new Scalar(
  "statusSupport_adsl_reset",
  "adsl_reset",
);

var statusSupport_wan_reset = new Scalar(
  "statusSupport_wan_reset",
  "wan_reset",
);
var statusSupport_ipv6wan_reset = new Scalar(
  "statusSupport_ipv6wan_reset",
  "ipv6wan_reset",
); //20140626
var statusSupport_atm_reset = new Scalar(
  "statusSupport_atm_reset",
  "atm_reset",
); //201400814

var statusSupport_lan_reset = new Scalar(
  "statusSupport_lan_reset",
  "lan_reset",
);

var settingstr069_inform = new Scalar("settingstr069_inform", "tr069_inform");
var settingstr069_inform_interval = new Scalar(
  "settingstr069_inform_interval",
  "tr069_inform_interval",
);
var settingstr069_acs_url = new Scalar(
  "settingstr069_acs_url",
  "tr069_acs_url",
);
var settingstr069_acs_username = new Scalar(
  "settingstr069_acs_username",
  "tr069_acs_username",
);
var settingstr069_acs_password = new Scalar(
  "settingstr069_acs_password",
  "tr069_acs_password",
);
var settingstr069_request_username = new Scalar(
  "settingstr069_request_username",
  "tr069_request_username",
);
var settingstr069_request_password = new Scalar(
  "settingstr069_request_password",
  "tr069_request_password",
);

var settingInternet_Time_Zone = new Scalar(
  "settingInternet_Time_Zone",
  "time_zone",
);
var settingInternet_synchronize = new Scalar(
  "settingInternet_synchronize",
  "time_synchronize",
);
var settingInternet_update_period = new Scalar(
  "settingInternet_update_period",
  "time_update_period",
);
var settingInternet_retry_interval = new Scalar(
  "settingInternet_retry_interval",
  "time_retry_interval",
);
var settingInternet_ntp1 = new Scalar("settingInternet_ntp1", "time_ntp1");
var settingInternet_ntp2 = new Scalar("settingInternet_ntp2", "time_ntp2");
var settingInternet_ntp3 = new Scalar("settingInternet_ntp3", "time_ntp3");
var settingInternet_ntp4 = new Scalar("settingInternet_ntp4", "time_ntp4");
var settingInternet_ntp5 = new Scalar("settingInternet_ntp5", "time_ntp5");
//luis add end

var overviewSetDeviceMAC = new Scalar("overviewSetDeviceMAC", "mac");
var overviewSetDeviceIcon = new Scalar("overviewSetDeviceIcon", "type");
var overviewSetDeviceName = new Scalar("overviewSetDeviceName", "name");

//activation
var ActivationUserChoose = new Scalar("activation", "wan_user_choose");
var ResetWanFibre = new Scalar("activation", "reset_wan_fibre");
var ResetWanDsl = new Scalar("activation", "reset_wan_dsl");
var WPSStart = new Scalar("activation", "wps_start");
var AuthUsername = new Scalar("activation", "ppp_auth_username");
var AuthPassword = new Scalar("activation", "ppp_auth_password");
var RestartWIFI = new Scalar("activation", "wifi_start");

//umts_activation
var umtsa_next_pageid = new Scalar("umts_activation", "next_pageid");
var umtsa_wait_time = new Scalar("umts_activation", "wait_time");
var umtsa_PIN = new Scalar("umts_activation", "PIN");
var umtsa_New_PIN = new Scalar("umts_activation", "New_PIN");
var umtsa_Repeat_New_PIN = new Scalar("umts_activation", "Repeat_New_PIN");
var umtsa_Save_PIN = new Scalar("umts_activation", "Save_PIN");
var umtsa_Deactivate_PIN = new Scalar("umts_activation", "Deactivate_PIN");
var umtsa_PIN_stat = new Scalar("umts_activation", "PIN_stat");
var umtsa_PUK = new Scalar("umts_activation", "PUK");
var umtsa_PUK_stat = new Scalar("umts_activation", "PUK_stat");
var umtsa_Connection = new Scalar("umts_activation", "Connection");
var umtsa_Signal_Strength = new Scalar("umts_activation", "Signal_Strength");
var umtsa_Download_Speed = new Scalar("umts_activation", "Download_Speed");
var umtsa_Upload_Speed = new Scalar("umts_activation", "Upload_Speed");
var umtsa_Downloaded_Data = new Scalar("umts_activation", "Downloaded_Data");
var umtsa_Uploaded_Data = new Scalar("umts_activation", "Uploaded_Data");
var umtsa_Uptime = new Scalar("umts_activation", "Uptime");
//var umtsa_ = new Scalar("umts_activation", "");

var umtsa_Mobile_Confirm = new Scalar("umts_activation", "Mobile_Confirm");
var umtsa_UMTS_Number = new Scalar("umts_activation", "UMTS_Number");

var interception_connection_continue = new Scalar(
  "interception_connection_continue",
  "continue",
);
var interception_connection_retry = new Scalar(
  "interception_connection_retry",
  "connection_retry",
);
var interception_connection_pageid = new Scalar(
  "interception_connection_pageid",
  "pageid",
);

// GPON page
var gpon_serial_number = new Scalar("settings_gpon", "serial_number");
var gpon_ploam_password = new Scalar("settings_gpon", "ploam_password");
var gpon_loid = new Scalar("settings_gpon", "loid");
var gpon_olt_type = new Scalar("settings_gpon", "olt_type");
var gpon_olt_auto_detect = new Scalar("settings_gpon", "olt_auto_detect");

// GPON Debug
var gpon_debug_debug_mode = new Scalar("gpon_debug", "debug_mode");
var gpon_debug_enable_omci_packet_trace = new Scalar(
  "gpon_debug",
  "enable_omci_packet_trace",
);
var gpon_debug_enable_omci_process_log = new Scalar(
  "gpon_debug",
  "enable_omci_process_log",
);
var gpon_debug_anti_rogueont = new Scalar("gpon_debug", "anti_rogueont");
var gpon_debug_tx_threshold = new Scalar("gpon_debug", "tx_threshold");

// gpon status
var statusSupport_gpon_status_reset = new Scalar(
  "statusSupport_gpon_status_reset",
  "gpon_status_reset",
);

// lan switch
var lan_switch_eth1 = new Scalar("lan_switch", "eth1");
var lan_switch_eth2 = new Scalar("lan_switch", "eth2");
var lan_switch_eth3 = new Scalar("lan_switch", "eth3");
var lan_switch_eth4 = new Scalar("lan_switch", "eth4");
var lan_switch_control_domain1 = new Scalar("lan_switch", "control_domain1");
var lan_switch_control_domain2 = new Scalar("lan_switch", "control_domain2");
var lan_switch_control_domain3 = new Scalar("lan_switch", "control_domain3");
var lan_switch_control_domain4 = new Scalar("lan_switch", "control_domain4");

// trace route
var trace_route_ip = new Scalar("statussupport_trace_route", "ip");
var trace_route_packet_size = new Scalar(
  "statussupport_trace_route",
  "packet_size",
);
var trace_route_times_to_trace = new Scalar(
  "statussupport_trace_route",
  "times_to_trace",
);

var StatusAndSupportEventLogAppLogSelect = new Scalar(
  "StatusAndSupportEventLogAppLogSelect",
  "applog_select",
);

var settingsIGMPProxyEnable = new Scalar(
  "settingsIGMPProxyEnable",
  "igmp_proxy",
);
var settingsIGMPProxyNetworkInterface = new Scalar(
  "settingsIGMPProxyNetworkInterface",
  "network_interface",
);
var settingsIGMPProxyMaxGroups = new Scalar(
  "settingsIGMPProxyMaxGroups",
  "max_groups",
);
var settingsIGMPProxyMaxHosts = new Scalar(
  "settingsIGMPProxyMaxHosts",
  "max_hosts",
);
var settingsIGMPProxyRobustness = new Scalar(
  "settingsIGMPProxyRobustness",
  "robustness",
);
var settingsIGMPProxyQuerierVersion = new Scalar(
  "settingsIGMPProxyQuerierVersion",
  "querier_version",
);
var settingsIGMPProxyQueryInterval = new Scalar(
  "settingsIGMPProxyQueryInterval",
  "query_interval",
);
var settingsIGMPProxyQueryResponseInterval = new Scalar(
  "settingsIGMPProxyQueryResponseInterval",
  "query_response_interval",
);
var settingsIGMPProxyUnsolicitedReportInterval = new Scalar(
  "settingsIGMPProxyUnsolicitedReportInterval",
  "unsolicited_report_interval",
);
var settingsIGMPProxyBootcastGroup = new Scalar(
  "settingsIGMPProxyBootcastGroup",
  "bootcast_group",
);
var settingsIGMPProxyWanIGMPVersion = new Scalar(
  "settingsIGMPProxyWanIGMPVersion",
  "wan_igmp_version",
);
var settingsIGMPProxyWanPeriodicInform = new Scalar(
  "settingsIGMPProxyWanPeriodicInform",
  "wan_periodic_inform",
);
var settingsIGMPProxyPeriodicInformInterval = new Scalar(
  "settingsIGMPProxyPeriodicInformInterval",
  "periodic_inform_interval",
);
var settingsIGMPProxyIGMPVersion = new Scalar(
  "settingsIGMPProxyIGMPVersion",
  "igmp_version",
);
var settingsIGMPProxyIPGroup1 = new Scalar(
  "settingsIGMPProxyIPGroup1",
  "ip_group1",
);
var settingsIGMPProxyIPGroup2 = new Scalar(
  "settingsIGMPProxyIPGroup2",
  "ip_group2",
);
var settingsIGMPProxyIPGroup3 = new Scalar(
  "settingsIGMPProxyIPGroup3",
  "ip_group3",
);
var settingsIGMPProxyIPGroup4 = new Scalar(
  "settingsIGMPProxyIPGroup4",
  "ip_group4",
);

var settingsRateLimitRules = new Scalar(
  "settingsRateLimitRules",
  "rate_limit_rules",
);

var messagesCreateMessageSendTo = new Scalar(
  "messagesCreateMessageSendTo",
  "send_to",
);
var messagesCreateMessageMessage = new Scalar(
  "messagesCreateMessageMessage",
  "message",
);

var messagesInboxReadByID = new Scalar("messagesInboxReadByID", "read_id");
var messagesInboxDeleteByID = new Scalar(
  "messagesInboxDeleteByID",
  "delete_id",
);
var messagesInboxReplyID = new Scalar("messagesInboxReplyID", "reply_id");
var messagesInboxReplyMessage = new Scalar(
  "messagesInboxReplyMessage",
  "reply_message",
);

var messagesSentDeleteByID = new Scalar("messagesSentDeleteByID", "delete_id");

var messagesOutboxDeleteByID = new Scalar(
  "messagesOutboxDeleteByID",
  "delete_id",
);

var settings_modem_mode = new Scalar("settings_modem_mode", "modem_mode");

//sample
/*
var mainScreenLoggedIn = new Scalar("mainScreenLoggedIn", "mainScreenLoggedIn_out");
var mainWANIPaddr = new Scalar("mainWANIPaddr", "mainWANIPaddr_out");


//single
mainScreenLoggedIn.set("test", null, "filename");


//multi
var data_format = [
	{nameObj : mainScreenLoggedIn, value : "123"},
	{nameObj : mainWANIPaddr, value : "456"},
];
dataBatchSend(data_format, callback, "filename");


//call back
function callback(data, textStatus, jqXHR){
	//alert(data);
	alert(textStatus);
	//alert(jqXHR);
}
*/
//sample end
