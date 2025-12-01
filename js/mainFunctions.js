var debug_mode = false;
var logMessage = false;
var sys_sjcl_enable = true;
var sys_userprofile = "";
var usermode = "";
var sys_phone_service = true;
//var sys_messages_service = true;
var sys_usb_status = true;
var sys_iptv_status = true;
var sys_fon_status = true;
var sys_umts_status = true;
var sys_ipv6_status = true;
var sys_band_steering = true;
var sys_sfp_status = true;
var sys_openmodem_status = true;
var sys_openmodem_subpages_status = true;
var sys_smartapp_status = true;
var sys_vodafone_safe_netwok = false;
var sys_ipv6_configuration = true;
var sys_11ac_status = true;
var support_super_wifi = false;
var sys_super_wifi_mode = "";
var sys_is_super_wifi_mode_not_Active = true;
//var sys_is_default_password = false;
var sys_username = "";
var sys_dropDownBasExp = "";
var sys_pageid = "";
var sys_lang_code = "";
var sys_region_code = "";
var sys_delay_time = 0;
var sys_encryption_key = "";
var sys_jump_to_wizard = "";
var sys_logged_in_users = "";
var sys_mobile_support = true;
var sys_number_block = true;
var sys_info = {};
var windowWidth = $(window).width();

var sys_phone2_support = false;
var sys_static_nat_support = true;
var sys_vpn_settings_support = true;
var sys_ipv6_firewall_support = true;
var sys_router_mode = true;

var show_internet_mobile = false;
var show_internet_wolan = false;
var show_phone_ringschedule = false;
var show_wifi_clientmonitor = false;
var show_wifi_vfwifinetwork = false;
var show_wifi_bandsteering = false;
var show_wifi_analyser = false;
var show_settings_printersharing = false;
var show_settings_energysettings = false;
var show_settings_snmp = false;
var show_settings_mobile = false;
var show_settings_xdsl = false;
var show_ss_mobile = false;
var show_ss_vdsl = false;
var show_ss_fibre = false;
var sys_debug_fw = false;
var show_ss_dongle_connectivity = false;
var reset_pages_ary = undefined;

var sys_user_timeout = null;

jQuery.extend({
  getJSON2: function (url, callback) {
    return jQuery.get(
      url,
      null,
      function (data) {
        //sjcl decrypt
        if (sys_sjcl_enable) {
          data = sjcl.decrypt(getWebStorage("dk"), data);
        }
        //sjcl decrypt end

        data = jQuery.parseJSON(data);
        callback(data);
      },
      "text",
    );
  },
});

function main_init(page) {
  if (self == top) {
    document.documentElement.style.display = "block";
  } else {
    top.location = self.location;
  }

  $.ajax({
    type: "get",
    dataType: "json",
    url:
      "./data/user_data.json?_=" +
      new Date().getTime() +
      "&csrf_token=" +
      csrf_token,
    async: false,
    success: function (data) {
      //Invalid filter
      data = filterInvalidString(data);

      usermode = getUserData("usermode", data);
      sys_phone_service = getUserData("phone_service", data);
      sys_sfp_status = getUserData_trueOrFalse(
        "sfp_status",
        data,
        sys_sfp_status,
      );
      sys_openmodem_status = getUserData_trueOrFalse(
        "openmodem_status",
        data,
        sys_openmodem_status,
      );
      sys_openmodem_subpages_status = getUserData_trueOrFalse(
        "openmodem_subpages_status",
        data,
        sys_openmodem_subpages_status,
      );
      sys_static_nat_support = getUserData_trueOrFalse(
        "static_nat_support",
        data,
        sys_static_nat_support,
      );
      sys_vpn_settings_support = getUserData_trueOrFalse(
        "vpn_settings_support",
        data,
        sys_vpn_settings_support,
      );
      sys_ipv6_firewall_support = getUserData_trueOrFalse(
        "ipv6_firewall_support",
        data,
        sys_ipv6_firewall_support,
      );
      sys_router_mode = getUserData_trueOrFalse(
        "router_mode",
        data,
        sys_router_mode,
      );

      //sys_messages_service = getUserData('messages_service', data);
      sys_userprofile = getUserData("userprofile", data);
      sys_usb_status = getUserData("usb_status", data);
      sys_iptv_status = getUserData("iptv_status", data);
      sys_fon_status = getUserData("fon_status", data);
      sys_umts_status = getUserData("umts_status", data);
      sys_ipv6_status = getUserData("ipv6_status", data);
      sys_band_steering = getUserData("band_steering", data);
      sys_smartapp_status = getUserData("smartapp_status", data);
      sys_vodafone_safe_netwok = getUserData("vodafone_safe_netwok", data);
      sys_ipv6_configuration = getUserData("ipv6_configuration", data);
      sys_11ac_status = getUserData("11ac_status", data);
      //			sys_is_default_password = getUserData('is_default_password', data);
      sys_username = getUserData("username", data);
      sys_dropDownBasExp = getUserData("dropDownBasExp", data);
      sys_pageid = getUserData("pageid", data);
      sys_lang_code = getUserData("lang_code", data);
      sys_region_code = getUserData_string(
        "region_code",
        data,
        sys_region_code,
      );
      sys_logged_in_users = getUserData("logged_in_users", data);
      sys_mobile_support = getUserData("mobile_support", data);
      sys_number_block = getUserData("NumberBlock_status", data);
      sys_info.fw_version = getUserData("fw_version", data);
      sys_info.wan_ip4_addr = getUserData("wan_ip4_addr", data);
      sys_info.wan_ip6_addr = getUserData("wan_ip6_addr", data);
      sys_debug_fw = getUserData("debug_fw_flag", data);

      sys_phone2_support = getUserData("phone2_support", data);

      support_super_wifi = getUserData_trueOrFalse("support_super_wifi", data);

      sys_super_wifi_mode = getUserData_string(
        "super_wifi_mode",
        data,
        sys_super_wifi_mode,
      );
      sys_is_super_wifi_mode_not_Active = /Active/.test(sys_super_wifi_mode)
        ? false
        : true;

      show_internet_mobile = getUserData("show_internet_mobile", data);
      show_internet_wolan = getUserData("show_internet_wolan", data);
      show_phone_ringschedule = getUserData("show_phone_ringschedule", data);
      show_wifi_clientmonitor = getUserData("show_wifi_clientmonitor", data);
      show_wifi_vfwifinetwork = getUserData("show_wifi_vfwifinetwork", data);
      show_wifi_bandsteering = getUserData("show_wifi_bandsteering", data);
      show_wifi_analyser = getUserData("show_wifi_analyser", data);
      show_settings_printersharing = getUserData(
        "show_settings_printersharing",
        data,
      );
      show_settings_energysettings = getUserData(
        "show_settings_energysettings",
        data,
      );
      show_settings_snmp = getUserData("show_settings_snmp", data);
      show_settings_mobile = getUserData("show_settings_mobile", data);
      show_settings_xdsl = getUserData("show_settings_xdsl", data);
      show_ss_mobile = getUserData("show_ss_mobile", data);
      show_ss_vdsl = getUserData("show_ss_vdsl", data);
      show_ss_fibre = getUserData("show_ss_fibre", data);
      show_ss_dongle_connectivity = getUserData(
        "show_ss_dongle_connectivity",
        data,
      );

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
      _object_write_denied(window, ["usermode"]); // peter 07/07 '22

      _loginUserChkLoginTimeout_set();

      //			if(sys_is_default_password && usermode !== 'admin' && page !== 'settings'){
      //				window.parent.location = 'settings.html#sub=60';
      //			}else{
      page_data_init(page);
      //			}
    },
  });
}

function page_data_init(page) {
  var dropDownBasExp = sys_dropDownBasExp;
  if (usermode == "admin") dropDownBasExp = usermode;

  if (dropDownBasExp == "") {
    sys_dropDownBasExp = "basic";
    chkPageSelect(page, "basic");
    load_multi_lang_data();
    //
    var tmp_navigation = navigation_init(page, "basic");

    if (!(sys_phone_service || usermode == "admin")) {
      var tmp_ary = tmp_navigation;
      tmp_navigation = [];
      for (var key in tmp_ary) {
        if (tmp_ary[key].tab !== "phone") {
          tmp_navigation.push(tmp_ary[key]);
        }
      }
    }
    /*if(!sys_messages_service){
			var tmp_ary = tmp_navigation;
			tmp_navigation = [];
			for(var key in tmp_ary){
				if(tmp_ary[key].tab !== 'messages'){
					tmp_navigation.push(tmp_ary[key]);
				}
			}
		}*/
    //
    //
    var tmp_navigation_items = navigation_items_init(tmp_navigation);

    for (var key in tmp_navigation_items) {
      if (tmp_navigation_items[key] === page) {
        $("#look_4").addClass(
          "navigation-" +
            (parseInt(key, 10) + 1) +
            "of" +
            tmp_navigation_items.length,
        );
      }
    }
    //
    header_init(page, "basic", tmp_navigation_items);
    $("#subnavigation").html(
      _makeNavigation(tmp_navigation, tmp_navigation_items),
    );

    mobile_header_init(page, "basic", tmp_navigation, tmp_navigation_items);
  } else {
    chkPageSelect(page, dropDownBasExp);
    load_multi_lang_data();
    //
    var tmp_navigation = navigation_init(page, dropDownBasExp);

    if (!(sys_phone_service || usermode == "admin")) {
      var tmp_ary = tmp_navigation;
      tmp_navigation = [];
      for (var key in tmp_ary) {
        if (tmp_ary[key].tab !== "phone") {
          tmp_navigation.push(tmp_ary[key]);
        }
      }
    }
    /*if(!sys_messages_service){
			var tmp_ary = tmp_navigation;
			tmp_navigation = [];
			for(var key in tmp_ary){
				if(tmp_ary[key].tab !== 'messages'){
					tmp_navigation.push(tmp_ary[key]);
				}
			}
		}*/
    //
    //
    var tmp_navigation_items = navigation_items_init(tmp_navigation);

    for (var key in tmp_navigation_items) {
      if (tmp_navigation_items[key] === page) {
        $("#look_4").addClass(
          "navigation-" +
            (parseInt(key, 10) + 1) +
            "of" +
            tmp_navigation_items.length,
        );
      }
    }
    //
    header_init(page, dropDownBasExp, tmp_navigation_items);
    $("#subnavigation").html(
      _makeNavigation(tmp_navigation, tmp_navigation_items),
    );

    mobile_header_init(
      page,
      dropDownBasExp,
      tmp_navigation,
      tmp_navigation_items,
    );
  }

  //reset
  _get_reset_pages_status();

  //.resetButtonsShort
  $(".resetButtonsShort")
    .on("click", function () {
      if (false && window.console) console.log(".resetButtonsShort click");

      //set title(mobile)
      $(".resetBar h3.page-title-container")
        .text($("#content h1").first().text())
        .attr("alm", $("#content h1").first().text());

      $(".resetButtonsShort").hide();
      $(".resetBar").animate(
        { height: "show" },
        {
          complete: function () {
            _addEAA2Destination($("#resetWrap, #resetWrapMobile"), true);
          },
        },
      );
    })
    .off("keyup.resetButtonsShort")
    .on("keyup.resetButtonsShort", function (e) {
      if (e.keyCode == 13) {
        //enter key
        $(this).trigger("click");
      }
    });

  //.cancelR
  $(".cancelR").on("click", function () {
    if (false && window.console) console.log(".cancelR click");

    $(".resetBar").animate({ height: "hide" }, function () {
      $(".resetButtonsShort").fadeIn(function () {
        _addEAA2Destination($("#resetWrap, #resetWrapMobile"), true);
      });
    });
  });

  //.resetR
  $(".resetR").on("click", function () {
    if (false && window.console) console.log(".resetR click");

    // popup waiting box...
    var html = "";
    html += '<div class="popup resetWait">';
    html +=
      '<p class="title"><span id="lang700119">' +
      getHTMLString(700119) +
      "</span></p>";
    html += '<div class="row tC">';
    html += '<img src="img/icon-thinking.gif" alt="Loading...">';
    html += "</div>";
    html += "</div>";
    html += '<div class="blackBackground resetWait" style="">&nbsp;</div>';
    $(".white-background").append(html);
    _addEAA2Destination($(".white-background"), true);

    var tmp_id = _get_pages_reset_id_by_hashid(_get_pages_hashid());

    resetPages_reset_page.set(tmp_id, resetPages_reset_pageRet, "reset_pages");
  });
  //reset end

  //lang
  var html_out = "";
  if (sys_region_code == "sp_else") {
    html_out +=
      '<li class="language-switcher"><a href="javascript:lang_change(\'sp_eles\');" tid="0" alm="Español">Español</a></li>';
  } else if (sys_region_code == "cz_else") {
    html_out +=
      '<li class="language-switcher"><a href="javascript:lang_change(\'cz_eles\');" tid="0" alm="Czech">Czech</a></li>';
  } else {
    html_out +=
      '<li class="language-switcher"><a href="javascript:lang_change(\'it_eles\');" tid="0" alm="Italian">Italian</a></li>';
  }
  html_out +=
    '<li class="language-switcher"><a href="javascript:lang_change(\'en_eles\');" tid="0" alm="English">English</a></li>';
  $("#language-switcher-list").html(html_out);

  //fw version & ip4/ip6 addr
  var html_out = "";
  html_out +=
    '<span class="language-string" tid="0" alm="' +
    getHTMLString(1310025).replace("%s", sys_info.fw_version) +
    '">' +
    getHTMLString(1310025).replace("%s", sys_info.fw_version) +
    "</span><br>"; //Firmware version: %s
  html_out +=
    '<span class="language-string" tid="0" alm="' +
    getHTMLString(1310026).replace("%s", sys_info.wan_ip4_addr) +
    '">' +
    getHTMLString(1310026).replace("%s", sys_info.wan_ip4_addr) +
    "</span><br>"; //WAN IPv4 Address: %s
  if (sys_ipv6_status && sys_ipv6_configuration) {
    html_out +=
      '<span class="language-string" tid="0" alm="' +
      getHTMLString(1310027).replace("%s", sys_info.wan_ip6_addr) +
      '">' +
      getHTMLString(1310027).replace("%s", sys_info.wan_ip6_addr) +
      "</span>"; //WAN IPv6 Address: %s
  }
  $("#info").html(html_out);

  GMSG_get_global_msg_status();

  $(window).resize(function () {
    if ($(window).width() != windowWidth) {
      windowWidth = $(window).width();

      $(".window_resize").trigger("pre_window_resize");

      clearTimeout(window.resizedFinished);
      window.resizedFinished = setTimeout(function () {
        $(".window_resize").trigger("window_resize");
      }, 100);
    }
  });

  $("#navigation a, #top-bar-content a").click(function () {
    if (chkUserDataModification()) return false;
  });

  $("select.dropdown")
    .chosen({
      disable_search_threshold: 100000,
      allow_single_deselect: true,
    })
    .on("change", function () {
      var selectedText = $(this).find("option:selected").text();

      // Update the live region to announce the selection
      //$('#announcement').text(`${getHTMLString("SELECTED")}:`+ selectedText);
      // Announce the selected option
      //$('#announcement').attr('aria-live', 'assertive').attr('role', 'alert');
      eaa_announceAction(`${getHTMLString("SELECTED")}:` + selectedText, {
        "aria-live": "assertive",
        role: "alert",
      });

      if ($(this).val() === "basic") {
        setUserData("dropDownBasExp", "basic");
      } else if ($(this).val() === "expert") {
        setUserData("dropDownBasExp", "expert");
      } else if ($(this).val() === "admin") {
        setUserData("dropDownBasExp", "admin");
      } else if ($(this).val() === "logout") {
        $("#logout").trigger("click");
      }
    })
    // When the dropdown opens, announce the first option if focused
    .on("chosen:showing_dropdown", function (e, params) {
      var firstOptionText = $(this).find("option").first().text();
      //$('#announcement').text('Dropdown opened. First option: ' + firstOptionText);
      //$('#announcement').attr('aria-live', 'polite').attr('role', 'alert');
      eaa_announceAction("Dropdown opened. First option: " + firstOptionText, {
        "aria-live": "polite",
        role: "alert",
      });
    });
  /*.on('chosen:showing_dropdown', function(){
		if(chkUserDataModification()) return false;
		
		if($(this).val() === "logout"){
			$('#logout').trigger("click");
		}
	}).on('chosen:hiding_dropdown', function(){
		if(chkUserDataModification()) return false;
		
		if($(this).val() === "logout"){
			$('#logout').trigger("click");
		}
	})*/

  $("#logout").on("click", function () {
    if (chkUserDataModification()) return false;

    delCookie("dropDownBasExp");
    delCookie("pageid");
    delCookie("username");
    delCookie("lang_code");
    delCookie("region_code");

    window.parent.location = "login.html";
  });

  //mobile
  $("a.mobile-navigation-item-title")
    .on("click", function () {
      if (logMessage && window.console)
        console.log("a.mobile-navigation-item-title click");

      var tmp_obj = $(this).closest("li");
      var tmp_first_item = tmp_obj.hasClass("first-item");
      var tmp_active = tmp_obj.hasClass("active");
      if (tmp_first_item) {
        //overview page
        if (chkUserDataModification()) return false;

        $("body").removeClass("menu-overlay-active");
        return true;
      }

      $("li.main-item").removeClass("active");

      if (!tmp_active) {
        tmp_obj.addClass("active");
      }
    })
    .on("keyup", function (e) {
      if (e.keyCode == 13) {
        //enter key
        $(this).trigger("click");
      }
    });

  $("li.mobile-navigation-item > a, li.navigation-item > a").on(
    "click",
    function () {
      if (logMessage && window.console)
        console.log(
          "li.mobile-navigation-item > a, li.navigation-item > a click",
        );

      if (chkUserDataModification()) return false;

      $("body").removeClass("menu-overlay-active");
    },
  );

  $("a.mobile_logout").on("click", function () {
    $("body").removeClass("menu-overlay-active");
    $("#logout").trigger("click");
  });

  $("#mobile-header .hamburger-menu, #mobile-menu-overlay .hamburger-menu")
    .on("click", function () {
      if (logMessage && window.console)
        console.log(
          "#mobile-header .hamburger-menu, #mobile-menu-overlay .hamburger-menu click",
        );

      $("body").toggleClass("menu-overlay-active");
      _addEAA2Destination($("body"), false);
    })
    .on("keyup", function (e) {
      if (e.keyCode == 13) {
        //enter key
        $(this).trigger("click");
      }
    });

  $(".warning-messages, #content-wrap").on("click", function () {
    if (logMessage && window.console)
      console.log(".warning-messages, #content-wrap click");

    if ($("body").hasClass("menu-overlay-active")) {
      $("body").removeClass("menu-overlay-active");
    }
  });
  //mobile end

  _addEAA2Destination($("body"), true);

  if (page == "overview") {
    page_overview_init();
  } else {
    page_data_load(page);
  }
}

function getUserData(name, data) {
  var tmp_phone_service = true;
  var tmp_usb_status = true;
  var tmp_iptv_status = true;
  var tmp_debug_fw = false;
  var tmp_fon_status = false;
  var tmp_umts_status = true;
  var tmp_ipv6_status = true;
  var tmp_band_steering = true;
  var tmp_smartapp_status = true;
  var tmp_vodafone_safe_netwok = false;
  var tmp_ipv6_configuration = true;
  var tmp_11ac_status = true;
  //	var tmp_is_default_password = false;
  var tmp_userprofile = "";
  var tmp_username = "";
  var tmp_usermode = "";
  var tmp_pageid = "";
  var tmp_dropDownBasExp = "";
  var tmp_lang_code = "";
  var tmp_delay_time = "";
  var tmp_encryption_key = "";
  var tmp_logged_in_users = "";
  var tmp_mobile_support = false;
  var tmp_number_block = false;
  var tmp_fw_version = "";
  var tmp_wan_ip4_addr = "";
  var tmp_wan_ip6_addr = "";
  var tmp_phone2_support = false;
  var tmp_jump_to_wizard = "";

  var tmp_show_internet_mobile = false;
  var tmp_show_internet_wolan = false;
  var tmp_show_phone_ringschedule = false;
  var tmp_show_wifi_clientmonitor = false;
  var tmp_show_wifi_vfwifinetwork = false;
  var tmp_show_wifi_bandsteering = false;
  var tmp_show_wifi_analyser = true;
  var tmp_show_settings_printersharing = false;
  var tmp_show_settings_energysettings = false;
  var tmp_show_settings_snmp = false;
  var tmp_show_settings_mobile = false;
  var tmp_show_settings_xdsl = false;
  var tmp_show_ss_mobile = false;
  var tmp_show_ss_vdsl = false;
  var tmp_show_ss_fibre = false;
  var tmp_show_ss_dongle_connectivity = false;

  var ret = false;

  $.each(data, function (main_key, main_val) {
    $.each(main_val, function (key, val) {
      if (key == "phone_service") {
        if (val == "1") tmp_phone_service = true;
        else tmp_phone_service = false;
      }
      if (key == "userprofile") {
        tmp_userprofile = val;
      }

      if (key == "usb_status") {
        if (val == "1") tmp_usb_status = true;
        else tmp_usb_status = false;
      }
      if (key == "iptv_status") {
        if (val == "1") tmp_iptv_status = true;
        else tmp_iptv_status = false;
      }
      if (key == "debug_fw_flag") {
        if (val == "1") tmp_debug_fw = true;
        else tmp_debug_fw = false;
      }
      if (key == "fon_status") {
        if (val == "1") tmp_fon_status = true;
        else tmp_fon_status = false;
      }
      if (key == "umts_status") {
        if (val == "1") tmp_umts_status = true;
        else tmp_umts_status = false;
      }
      if (key == "ipv6_status") {
        if (val == "1") tmp_ipv6_status = true;
        else tmp_ipv6_status = false;
      }
      if (key == "band_steering") {
        if (val == "1") tmp_band_steering = true;
        else tmp_band_steering = false;
      }
      if (key == "smartapp_status") {
        tmp_smartapp_status = val == "1";
      }
      if (key == "vodafone_safe_netwok") {
        if (val == "1") tmp_vodafone_safe_netwok = true;
        else tmp_vodafone_safe_netwok = false;
      }
      if (key == "ipv6_configuration") {
        if (val == "1") tmp_ipv6_configuration = true;
        else tmp_ipv6_configuration = false;
      }
      if (key == "11ac_status") {
        if (val == "1") tmp_11ac_status = true;
        else tmp_11ac_status = false;
      }
      //			if(key == "is_default_password"){
      //				tmp_is_default_password = (val == '1')? true : false;
      //			}
      if (key == "sfp_status") {
        if (name == "sfp_status") {
          ret = val == "1" ? true : false;
        }
      }

      if (key == "username") tmp_username = val;
      if (key == "usermode") tmp_usermode = val;
      if (key == "pageid") tmp_pageid = val;
      if (key == "dropDownBasExp") tmp_dropDownBasExp = val;
      if (key == "lang_code") tmp_lang_code = val;
      if (key == "delay_time") tmp_delay_time = val;
      if (key == "encryption_key") tmp_encryption_key = val;
      if (key == "jump_to_wizard") tmp_jump_to_wizard = val;
      if (key == "logged_in_users") tmp_logged_in_users = val;
      if (key == "mobile_support") tmp_mobile_support = val == "1";
      if (key == "NumberBlock_status") tmp_number_block = val == "1";
      if (key == "fw_version") tmp_fw_version = val;
      if (key == "wan_ip4_addr") tmp_wan_ip4_addr = val;
      if (key == "wan_ip6_addr") tmp_wan_ip6_addr = val;
      if (key == "phone2_support") tmp_phone2_support = val == "1";

      if (key == "show_internet_mobile") tmp_show_internet_mobile = val == "1";
      if (key == "show_internet_wolan") tmp_show_internet_wolan = val == "1";
      if (key == "show_phone_ringschedule")
        tmp_show_phone_ringschedule = val == "1";
      if (key == "show_wifi_clientmonitor")
        tmp_show_wifi_clientmonitor = val == "1";
      if (key == "show_wifi_vfwifinetwork")
        tmp_show_wifi_vfwifinetwork = val == "1";
      if (key == "show_wifi_bandsteering")
        tmp_show_wifi_bandsteering = val == "1";
      if (key == "show_wifi_analyser") tmp_show_wifi_analyser = val == "1";
      if (key == "show_settings_printersharing")
        tmp_show_settings_printersharing = val == "1";
      if (key == "show_settings_energysettings")
        tmp_show_settings_energysettings = val == "1";
      if (key == "show_settings_snmp") tmp_show_settings_snmp = val == "1";
      if (key == "show_settings_mobile") tmp_show_settings_mobile = val == "1";
      if (key == "show_settings_xdsl") tmp_show_settings_xdsl = val == "1";
      if (key == "show_ss_mobile") tmp_show_ss_mobile = val == "1";
      if (key == "show_ss_vdsl") tmp_show_ss_vdsl = val == "1";
      if (key == "show_ss_fibre") tmp_show_ss_fibre = val == "1";
      if (key == "show_ss_dongle_connectivity")
        tmp_show_ss_dongle_connectivity = val == "1";
    });
  });
  if (name == "sfp_status") {
    return ret;
  }

  if (name == "userprofile") return tmp_userprofile;
  if (name == "phone_service") return tmp_phone_service;
  if (name == "usb_status") return tmp_usb_status;
  if (name == "iptv_status") return tmp_iptv_status;
  if (name == "debug_fw_flag") return tmp_debug_fw;
  if (name == "fon_status") return tmp_fon_status;
  if (name == "umts_status") return tmp_umts_status;
  if (name == "ipv6_status") return tmp_ipv6_status;
  if (name == "band_steering") return tmp_band_steering;
  if (name == "smartapp_status") return tmp_smartapp_status;
  if (name == "vodafone_safe_netwok") return tmp_vodafone_safe_netwok;
  if (name == "ipv6_configuration") return tmp_ipv6_configuration;
  if (name == "11ac_status") return tmp_11ac_status;
  //	if(name == 'is_default_password') return tmp_is_default_password;
  if (name == "username") return tmp_username;
  if (name == "usermode") return tmp_usermode;
  if (name == "pageid") return tmp_pageid;
  if (name == "dropDownBasExp") return tmp_dropDownBasExp;
  if (name == "lang_code") return tmp_lang_code;
  if (name == "delay_time") return tmp_delay_time;
  if (name == "encryption_key") return tmp_encryption_key;
  if (name == "jump_to_wizard") return tmp_jump_to_wizard;
  if (name == "logged_in_users") return tmp_logged_in_users;
  if (name == "mobile_support") return tmp_mobile_support;
  if (name == "NumberBlock_status") return tmp_number_block;
  if (name == "fw_version") return tmp_fw_version;
  if (name == "wan_ip4_addr") return tmp_wan_ip4_addr;
  if (name == "wan_ip6_addr") return tmp_wan_ip6_addr;
  if (name == "phone2_support") return tmp_phone2_support;

  if (name == "show_internet_mobile") return tmp_show_internet_mobile;
  if (name == "show_internet_wolan") return tmp_show_internet_wolan;
  if (name == "show_phone_ringschedule") return tmp_show_phone_ringschedule;
  if (name == "show_wifi_clientmonitor") return tmp_show_wifi_clientmonitor;
  if (name == "show_wifi_vfwifinetwork") return tmp_show_wifi_vfwifinetwork;
  if (name == "show_wifi_bandsteering") return tmp_show_wifi_bandsteering;
  if (name == "show_wifi_analyser") return tmp_show_wifi_analyser;
  if (name == "show_settings_printersharing")
    return tmp_show_settings_printersharing;
  if (name == "show_settings_energysettings")
    return tmp_show_settings_energysettings;
  if (name == "show_settings_snmp") return tmp_show_settings_snmp;
  if (name == "show_settings_mobile") return tmp_show_settings_mobile;
  if (name == "show_settings_xdsl") return tmp_show_settings_xdsl;
  if (name == "show_ss_mobile") return tmp_show_ss_mobile;
  if (name == "show_ss_vdsl") return tmp_show_ss_vdsl;
  if (name == "show_ss_fibre") return tmp_show_ss_fibre;
  if (name == "show_ss_dongle_connectivity")
    return tmp_show_ss_dongle_connectivity;
}

function getUserData_trueOrFalse(name, data, initValue) {
  var ret = initValue;

  $.each(data, function (main_key, main_val) {
    $.each(main_val, function (key, val) {
      if (key == name) {
        ret = val == "1" ? true : false;
      }
    });
  });
  return ret;
}

function getUserData_string(name, data, initValue) {
  var ret = initValue;

  $.each(data, function (main_key, main_val) {
    $.each(main_val, function (key, val) {
      if (key == name) {
        ret = val;
      }
    });
  });
  return ret;
}

function setUserData(data, val) {
  if (chkUserDataModification()) return false;

  if (data == "dropDownBasExp") {
    sys_dropDownBasExp = val;
    userDataDropDownBasExp.set(val, userDataDropDownBasExpRet, "user_data");
  }
  if (data == "pageid") {
    sys_pageid = val;
    userDataPageId.set(val, null, "user_data");
  }
  if (data == "lang_code") {
    sys_lang_code = val;
    userDataLangCode.set(val, userDataLangCodeRet, "user_data");
  }
}

function setUserLang(data, val) {
  if (data == "lang_code") {
    sys_lang_code = val;
    userDataLangCode.set(val, userDataLangCodeRet, "user_lang");
  }
}

function setWebStorage(c_name, value) {
  if (typeof Storage !== "undefined") {
    sessionStorage.setItem(c_name, value);
  } else {
    setCookie(c_name, value, 1);
  }
}

function getWebStorage(c_name) {
  if (typeof Storage !== "undefined") {
    return sessionStorage.getItem(c_name);
  } else {
    return getCookie(c_name);
  }
}

function setCookie(c_name, value, exdays) {
  //alert(c_name + ":" + value);
  var exdate = new Date();
  exdate.setDate(exdate.getDate() + exdays);
  var c_value =
    escape(value) + (exdays == null ? "" : "; expires=" + exdate.toUTCString());
  document.cookie = c_name + "=" + c_value;
}

function getCookie(c_name) {
  var c_value = document.cookie;
  var c_start = c_value.indexOf(" " + c_name + "=");
  if (c_start == -1) {
    c_start = c_value.indexOf(c_name + "=");
  }
  if (c_start == -1) {
    c_value = null;
  } else {
    c_start = c_value.indexOf("=", c_start) + 1;
    var c_end = c_value.indexOf(";", c_start);
    if (c_end == -1) {
      c_end = c_value.length;
    }
    c_value = unescape(c_value.substring(c_start, c_end));
  }
  return c_value;
}

function delCookie(c_name) {
  var exdate = new Date();
  exdate.setDate(exdate.getDate() - 1);
  var value = getCookie(c_name);
  var c_value = escape(value) + "; expires=" + exdate.toUTCString();
  document.cookie = c_name + "=" + c_value;
}

function in_array(stringToSearch, arrayToSearch) {
  if (arrayToSearch !== undefined) {
    for (s = 0; s < arrayToSearch.length; s++) {
      thisEntry = arrayToSearch[s].toString();
      if (thisEntry == stringToSearch) {
        return true;
      }
    }
  }
  return false;
}

function isBrowserDetectSupport() {
  navigator.sayswho = (function () {
    var ua = navigator.userAgent,
      tem,
      M =
        ua.match(
          /(opera|chrome|safari|firefox|msie|trident(?=\/))\/?\s*(\d+)/i,
        ) || [];
    if (/trident/i.test(M[1])) {
      tem = /\brv[ :]+(\d+)/g.exec(ua) || [];
      return "IE " + (tem[1] || "");
    }
    if (M[1] === "Chrome") {
      tem = ua.match(/\b(OPR|Edge)\/(\d+)/);
      if (tem != null) return tem.slice(1).join(" ").replace("OPR", "Opera");
    }
    M = M[2] ? [M[1], M[2]] : [navigator.appName, navigator.appVersion, "-?"];
    if ((tem = ua.match(/version\/(\d+)/i)) != null) M.splice(1, 1, tem[1]);
    return M.join(" ");
  })();

  if (navigator.sayswho.indexOf("MSIE") !== -1) {
    var tmp_version = parseInt(navigator.sayswho.replace("MSIE ", ""), 10);

    if (tmp_version < 8) {
      return false;
    }
  }

  return true;
}

function loginUserChkLoginTimeoutRet(data, textStatus, jqXHR) {
  _loginUserChkLoginTimeout_clear();

  if (data.length < 3) {
    _loginUserChkLoginTimeout_popup();
  } else {
    var status = data.slice(0, 3);
    if (status != "[ ]") {
      _loginUserChkLoginTimeout_popup();
    } else {
      _loginUserChkLoginTimeout_set();
    }
  }
}

function _loginUserChkLoginTimeout_set() {
  if (sys_user_timeout == null) {
    sys_user_timeout = setInterval(function () {
      loginUserChkLoginTimeout.set(
        sys_username,
        loginUserChkLoginTimeoutRet,
        "login",
      );
    }, 60000);
  }
}

function _loginUserChkLoginTimeout_clear() {
  clearInterval(sys_user_timeout);
  sys_user_timeout = null;
}

function _loginUserChkLoginTimeout_popup() {
  if ($(".blackBackground_logout").length == 0) {
    $("body").append(
      '<div class="blackBackground_logout" style="display: none;">&nbsp;</div>',
    );
  }

  if ($(".popup_logout").length == 0) {
    var html = "";
    html += '<div class="popup_logout" style="display: none;">';
    html +=
      '<p class="title tL"><span tid="0" al="ACTIVATION_PAGE_LOGOUT_TITLE">' +
      getHTMLString("ACTIVATION_PAGE_LOGOUT_TITLE") +
      "</span></p>"; //Session Timeout
    html += '<div class="row" style="font-weight: normal;">';
    html += '<div class="left">';
    html +=
      '<span tid="0" al="ACTIVATION_PAGE_LOGOUT_REDIRECTED">' +
      getHTMLString("ACTIVATION_PAGE_LOGOUT_REDIRECTED") +
      "</span>"; //You will be redirected to Login page
    html += "</div>";
    html += "</div>";
    html += '<div class="apply-cancel">';
    html +=
      '<input value="' +
      getHTMLString("ACTIVATION_PAGE_LOGOUT_BTN_OK") +
      '" class="button button-apply" type="button" tid="0" al="ACTIVATION_PAGE_LOGOUT_BTN_OK">'; //OK
    html += "</div>";
    html += "</div>";

    $("body").append(html);

    $(".popup_logout .button-apply").on("click", function () {
      if (false && window.console)
        console.log(".popup.popup_logout .button-apply click");

      window.parent.location = "login.html";
    });
  }

  $("#header").hide();
  $("#content-wrap").hide();
  $("#footer").hide();

  $(".popup_logout, .blackBackground_logout").fadeIn(function () {
    removeEaaTidEvents($("body"));
    _addEAA2Destination($(".popup_logout"), true);
    eaa_loopTabKey($(".popup_logout"));
  });
}

function userDataDropDownBasExpRet(data, textStatus, jqXHR) {
  if (data == "1") {
    location.reload();
  }
}

function userDataLangCodeRet(data, textStatus, jqXHR) {
  if (data == "1") {
    window.setTimeout(function () {
      location.reload();
    }, 1000);
  }
}

function addChosen2Select(obj) {
  $("select", obj)
    .chosen({
      disable_search_threshold: 100000,
      allow_single_deselect: true,
    })
    .off("change.addChosen2Select")
    .on("change.addChosen2Select", function (e) {
      var selectedText = $(this).find("option:selected").text();

      // Update the live region to announce the selection
      //$('#announcement').text(`${getHTMLString("SELECTED")}:`+ selectedText);
      // Announce the selected option
      //$('#announcement').attr('aria-live', 'assertive').attr('role', 'alert');

      eaa_announceAction(`${getHTMLString("SELECTED")}:` + selectedText, {
        "aria-live": "assertive",
        role: "alert",
      });
    })
    // When the dropdown opens, announce the first option if focused
    .off("chosen:showing_dropdown.addChosen2Select")
    .on("chosen:showing_dropdown.addChosen2Select", function (e, params) {
      var firstOptionText = $(this).find("option").first().text();

      //$('#announcement').text('Dropdown opened. First option: ' + firstOptionText);
      //$('#announcement').attr('aria-live', 'polite').attr('role', 'alert');
      eaa_announceAction("Dropdown opened. First option: " + firstOptionText, {
        "aria-live": "polite",
        role: "alert",
      });
    });
}

function chkUserDataModification() {
  var modify_msg = $("#lang700175").closest(".message-arrowbox").css("display");
  //alert(modify_msg);

  if (modify_msg == undefined) return false;
  if (modify_msg != "none") {
    $("body").removeClass("menu-overlay-active");
    $("body, html").animate({ scrollTop: $("body").height() });

    return true;
  } else {
    return false;
  }
}

function scrollTopByObject(obj) {
  return obj.offset().top - 100 + "px";
}

function isFontElementOverflow(obj) {
  var _hasScrollBar = false;
  if (
    obj.clientHeight < obj.scrollHeight ||
    obj.clientWidth < obj.scrollWidth
  ) {
    _hasScrollBar = true;
  }
  return _hasScrollBar;
}

function isThisValNoMask(maskVal, thisVal) {
  if (maskVal == "NaN" || maskVal < 0 || maskVal.length > 8) return true;
  if (thisVal == "NaN" || thisVal < 0 || thisVal.length > 8) return true;

  var maskVal_ary = Array();
  var thisVal_ary = Array();

  for (var i = maskVal.length; i > 0; i--) {
    maskVal_ary.push(maskVal.slice(i - 1, i));
  }
  for (var i = 8 - maskVal.length; i > 0; i--) {
    maskVal_ary.push("0");
  }

  for (var i = thisVal.length; i > 0; i--) {
    thisVal_ary.push(thisVal.slice(i - 1, i));
  }
  for (var i = 8 - thisVal.length; i > 0; i--) {
    thisVal_ary.push("0");
  }

  for (var key in maskVal_ary) {
    if (maskVal_ary[key] == "0" && thisVal_ary[key] == "1") return true;
  }

  return false;
}

function getScriptByArray(ary, ret_func) {
  if (ary.length != 0) {
    var tmp_getScript = ary.pop();
    $.getScript(
      tmp_getScript +
        "?_=" +
        new Date().getTime() +
        "&csrf_token=" +
        csrf_token,
      function (response, status) {
        if (ary.length == 0) {
          if (ret_func != null) {
            ret_func(response, status);
          }
        } else {
          getScriptByArray(ary, ret_func);
        }
      },
    );
  }
}

function chkIsSysType(val) {
  if (sys_type === val) {
    return true;
  } else {
    return false;
  }
}

function chkIsNotSysType(val) {
  if (sys_type !== val) {
    return true;
  } else {
    return false;
  }
}

function calcPasswordStrength_level_0to5(password) {
  var score = 0;

  //if password bigger than 7 give 1 point
  if (password.length > 7) score++;

  //if password has both lower and uppercase characters give 1 point
  if (password.match(/[a-z]/) && password.match(/[A-Z]/)) score++;

  //if password has at least one number give 1 point
  if (password.match(/\d+/)) score++;

  //if password has at least one special caracther give 1 point
  if (password.match(/.[!,@,#,$,%,^,&,*,?,_,~,-,(,)]/)) score++;

  //if password bigger than 12 give another 1 point
  if (password.length > 12) score++;

  if (
    /^[a-zA-Z]+$/.exec(password) !== null ||
    /^[0-9]+$/.exec(password) !== null ||
    /admin/.exec(password.toLowerCase()) !== null ||
    /password/.exec(password.toLowerCase()) !== null
  ) {
    if (Number(score) !== 0) {
      score--;
    }
  }

  return score;
}

function passwordStrengthHtml(password, obj) {
  var score = calcPasswordStrength_level_0to5(password);

  var desc = new Array();
  /*
	desc[0] = '<span>'+getHTMLString(700231)+'</span>'; //Very Weak
	desc[1] = '<span>'+getHTMLString(700232)+'</span>'; //Weak
	desc[2] = '<span>'+getHTMLString(700233)+'</span>'; //Better
	desc[3] = '<span>'+getHTMLString(700234)+'</span>'; //Medium
	desc[4] = '<span>'+getHTMLString(700235)+'</span>'; //Strong
	desc[5] = '<span>'+getHTMLString(700236)+'</span>'; //Strongest
    */
  desc[0] =
    '<span tabindex="0" aria-label=' +
    getHTMLString(700232) +
    ">" +
    getHTMLString(700232) +
    "</span>"; //Weak
  desc[1] =
    '<span tabindex="0" aria-label=' +
    getHTMLString(700232) +
    ">" +
    getHTMLString(700232) +
    "</span>"; //Weak
  desc[2] =
    '<span tabindex="0" aria-label=' +
    getHTMLString(700241) +
    ">" +
    getHTMLString(700241) +
    "</span>"; //Good
  desc[3] =
    '<span tabindex="0" aria-label=' +
    getHTMLString(700241) +
    ">" +
    getHTMLString(700241) +
    "</span>"; //Good
  desc[4] =
    '<span tabindex="0" aria-label=' +
    getHTMLString(700235) +
    ">" +
    getHTMLString(700235) +
    "</span>"; //Strong
  desc[5] =
    '<span tabindex="0" aria-label=' +
    getHTMLString(700235) +
    ">" +
    getHTMLString(700235) +
    "</span>"; //Strong

  if (typeof obj != "object") {
    return false;
  } else {
    obj
      .html(desc[score])
      .removeClass()
      .addClass("passwordStrength strength" + score);
    return true;
  }
}

function passwordStrength(password, obj) {
  var score = calcPasswordStrength_level_0to5(password);

  var desc = new Array();
  /*
	desc[0] = '<span>'+getHTMLString(700231)+'</span>'; //Very Weak
	desc[1] = '<span>'+getHTMLString(700232)+'</span>'; //Weak
	desc[2] = '<span>'+getHTMLString(700233)+'</span>'; //Better
	desc[3] = '<span>'+getHTMLString(700234)+'</span>'; //Medium
	desc[4] = '<span>'+getHTMLString(700235)+'</span>'; //Strong
	desc[5] = '<span>'+getHTMLString(700236)+'</span>'; //Strongest
    */
  desc[0] = '<span tid="0" al="700232">' + getHTMLString(700232) + "</span>"; //Weak
  desc[1] = '<span tid="0" al="700232">' + getHTMLString(700232) + "</span>"; //Weak
  desc[2] = '<span tid="0" al="700241">' + getHTMLString(700241) + "</span>"; //Good
  desc[3] = '<span tid="0" al="700241">' + getHTMLString(700241) + "</span>"; //Good
  desc[4] = '<span tid="0" al="700235">' + getHTMLString(700235) + "</span>"; //Strong
  desc[5] = '<span tid="0" al="700235">' + getHTMLString(700235) + "</span>"; //Strong

  if (typeof obj != "object") {
    return false;
  } else {
    obj
      .html(desc[score])
      .removeClass()
      .addClass("passwordStrength strength" + score);
    return true;
  }
}

function passwordStrength2(password, obj) {
  var score = calcPasswordStrength_level_0to5(password);

  var desc = new Array();
  desc[0] = '<span tid="0" al="700242">' + getHTMLString(700242) + "</span>"; //Weak Password
  desc[1] = '<span tid="0" al="700242">' + getHTMLString(700242) + "</span>"; //Weak Password
  desc[2] = '<span tid="0" al="700243">' + getHTMLString(700243) + "</span>"; //Good Password
  desc[3] = '<span tid="0" al="700243">' + getHTMLString(700243) + "</span>"; //Good Password
  desc[4] = '<span tid="0" al="700244">' + getHTMLString(700244) + "</span>"; //Strong Password
  desc[5] = '<span tid="0" al="700244">' + getHTMLString(700244) + "</span>"; //Strong Password

  if (typeof obj != "object") {
    return false;
  } else {
    obj
      .html(desc[score])
      .removeClass()
      .addClass("passwordStrength strength" + score);
    return true;
  }
}

//reset
function _get_reset_pages_status() {
  var JSONSource =
    "./data/reset_pages.json?_=" +
    new Date().getTime() +
    "&csrf_token=" +
    csrf_token;
  $.getJSON(JSONSource, function (data) {
    //Invalid filter
    data = filterInvalidString(data);

    reset_pages_ary = undefined;
    var x;
    for (x in data[0]) {
      if (x == "reset_pages") {
        reset_pages_ary = data[0].reset_pages.split(",");
      }
    }

    var tmp_id = _get_pages_reset_id_by_hashid(_get_pages_hashid());
    if (tmp_id !== "" && in_array(tmp_id, reset_pages_ary)) {
      $(".resetButtonsShort").show();
      $(".resetBar").hide();
      _addEAA2Destination($("#resetWrap, #resetWrapMobile"), true);
    } else {
      $(".resetButtonsShort").hide();
      $(".resetBar").hide();
      _addEAA2Destination($("#resetWrap, #resetWrapMobile"), true);
    }
  });
}

function resetPages_reset_pageRet(data, textStatus, jqXHR) {
  if (data == "1") {
    location.reload();
  } else {
    $(".resetWait").remove();
  }
}

function _get_pages_hashid() {
  var tmp_hashid = "";
  var tmp_class = $("#content").attr("class").split(" ");

  for (var key in tmp_class) {
    if (tmp_class[key].indexOf("sub") !== -1) {
      tmp_hashid = tmp_class[key].replace("sub", "");
    }
  }

  return tmp_hashid;
}

function _get_pages_reset_id_by_hashid(hashid) {
  var ret_id = "";
  var locationInfo = window.location.toString().split("#");
  var pageId = locationInfo[1];

  if (typeof pageId !== "undefined") {
    var navigation = [];
    if (usermode == "admin") {
      navigation = _obj_navigation_admin();
    } else {
      if (sys_dropDownBasExp == "basic") {
        navigation = _obj_navigation_basic();
      } else if (sys_dropDownBasExp == "expert") {
        navigation = _obj_navigation_expert();
      }
    }
  }

  ret_id = _get_array_id_by_hashid(hashid, navigation);

  return ret_id;
}

function _get_array_id_by_hashid(hashid, array) {
  var ret_id = "";
  var submenu_ret_id = "";

  for (var key in array) {
    if (array[key].hashid === hashid) {
      ret_id = array[key].id;
    } else {
      if (array[key].submenu.length !== 0) {
        submenu_ret_id = _get_array_id_by_hashid(hashid, array[key].submenu);
        if (submenu_ret_id !== "") {
          ret_id = submenu_ret_id;
        }
      }
    }
  }

  return ret_id;
}
//reset end

// peter 07/07 '22
var _object_write_denied = function (obj, arr) {
  var d = {};
  for (var key in arr) {
    if (obj[arr[key]]) {
      d[arr[key]] = { writable: false };
    }
  }
  Object.defineProperties(obj, d);
};

//EAA add 20250430
function removeEaaTidEvents(context) {
  var obj = context;

  var removed = ["a", "li", "input", "[tid]"];
  $(removed.join(","), obj).each(function (e) {
    $(this).attr("tabindex", "-1");
  });
  var chosen = [".chosen-container"];
  $(chosen.join(","), obj).each(function (e) {
    var _this = this;
    $(this).removeAttr("tabindex");
    $(this).removeAttr("aria-label");
  });
}

function _addEAA2Destination(context, _auto) {
  var obj = context;

  //remove all default tabindex events
  removeEaaTidEvents(obj);

  if (_auto) {
    $('span[class="language-string"], span[id^=lang]', obj).each(function (e) {
      if ($(this).hasClass("noEAA")) {
      } else {
        var tid = $(this).is("[tid]") ? $(this).attr("tid") : "0";
        $(this).attr("tid", tid);
        if (tid == "0") {
          if ($(this).is("[name]")) {
            $(this).attr("al", $(this).attr("name"));
          } else {
            $(this).attr("alm", $(this).text());
          }
        }
      }
    });
  }
  //search for all custom-defined attributes: "tid" and "al"
  //"tid" is a custom attribute, The tabindex value we want to define manually
  //tid="0" == tabindex="0"
  //"al" is a custom attribute, We use it to translate the string and apply the result to the aria-label
  //al="a,b,c" == aria-label="a b c"
  //al="multi-lag-id1,multi-lag-id2" == aria-label="multi-lag-string1 multi-lag-string2"
  var selected = ["[tid]", "[al]", "[alm]"];
  _setEaaForVisableObjects($(selected.join(","), obj));
  /*
	$(selected.join(","), obj).each(function(e){
		if($(this).is(":visible")){
			//console.log($(this).text());
			if($(this).is("[tid]")){
				$(this).attr("tabindex", $(this).attr("tid"));
			}
			//
			if($(this).is("[al]")){
				var als = $(this).attr("al").split(',');
				var str = '';
				for(var key in als){
					if(key > 0){ str += " "}
					str += getHTMLString(als[key]) == undefined ? als[key] : getHTMLString(als[key]);
				}
				$(this).attr("aria-label", str);
			}
			if($(this).is("[alm]")){
				var als = $(this).attr("alm");
				$(this).attr("aria-label", als);
			}
			//
			//event for enter key
			//checkbox and radio button
			if($(this).is("label[for]")){
				$(this).off('keyup').on('keyup', function(e){
					if(e.keyCode == 13){ //enter key
						$('#'+$(this).attr('for')).trigger('click');
					}
				});
			}
			//on off button
			if($(this).is(".button.button-off, .button.button-on")){
				$(this).off('keyup').on('keyup', function(e){
					if(e.keyCode == 13){ //enter key
						$(this).trigger('click');
					}
				});
			}
			//end event for enter key
		}else{
			$(this).removeAttr("tabindex");
			$(this).removeAttr("aria-label");
		}
	});
	*/
  var chosen = [".chosen-container"];
  $(chosen.join(","), obj).each(function (e) {
    var _this = this;
    if ($(this).is(":visible")) {
      //console.log($(this).prev('select'));
      if ($(this).prev("select").is("[tid]")) {
        var tid = $(this).prev("select").attr("tid");
        $(this).attr("tabindex", tid);
      }
      if ($(this).prev("select").is("[al]")) {
        var als = $(this).prev("select").attr("al").split(",");
        var str = "";
        for (var key in als) {
          if (key > 0) {
            str += " ";
          }
          str +=
            getHTMLString(als[key]) == undefined
              ? als[key]
              : getHTMLString(als[key]);
        }
        $(this).attr("aria-label", str);
      } else if ($(this).prev("select").is("[alm]")) {
        var str = $(this).prev("select").attr("alm");
        $(this).attr("aria-label", str);
      }
      //event for enter key
      $(this)
        .off("keyup.addEAA2Destination")
        .on("keyup.addEAA2Destination", function (e) {
          if (e.keyCode == 38 || e.keyCode == 40) {
            var selectedText = $(this).find("li.highlighted").text();

            // Update the live region to announce the selection
            //$('#announcement').text(`${getHTMLString("SELECTED")}: ` + selectedText);
            // Announce the selected option
            //$('#announcement').attr('aria-live', 'assertive').attr('role', 'alert');

            eaa_announceAction(
              `${getHTMLString("SELECTED")}: ` + selectedText,
              { "aria-live": "assertive", role: "alert" },
            );
          }
          if (e.keyCode == 13) {
            //enter key
            $(this).prev("select").trigger("chosen:open");
          }
        });
      //end event for enter key
    } else {
      $(this).removeAttr("tabindex");
      $(this).removeAttr("aria-label");
    }
  });
}

function setEAA(obj, tid, al, alm) {
  $(obj).attr("tid", tid);
  if (al) {
    var al_nodoublequa = al.replaceAll('"', "");
    $(obj).attr("al", al_nodoublequa);
  } else {
    if (alm) {
      var alm_nodoublequa = alm.replaceAll('"', "");
      $(obj).attr("alm", alm_nodoublequa.trim());
    }
  }
  _setEaaForVisableObjects(obj);
}

function _setEaaForVisableObjects(obj) {
  //search for all custom-defined attributes: "tid" and "al"
  //"tid" is a custom attribute, The tabindex value we want to define manually
  //tid="0" == tabindex="0"
  //"al" is a custom attribute, We use it to translate the string and apply the result to the aria-label
  //al="a,b,c" == aria-label="a b c"
  //al="multi-lag-id1,multi-lag-id2" == aria-label="multi-lag-string1 multi-lag-string2"

  $(obj).each(function (e) {
    if ($(this).is(":visible")) {
      //console.log($(this).text());
      if ($(this).is("[tid]")) {
        $(this).attr("tabindex", $(this).attr("tid"));
      }
      //
      if ($(this).is("[al]")) {
        var als = $(this).attr("al").split(",");
        var str = "";
        for (var key in als) {
          if (key > 0) {
            str += " ";
          }
          str +=
            getHTMLString(als[key]) == undefined
              ? als[key]
              : getHTMLString(als[key]);
        }
        $(this).attr("aria-label", str);
      }
      if ($(this).is("[alm]")) {
        var als = $(this).attr("alm");
        $(this).attr("aria-label", als);
      }
      //
      //event for enter key
      //checkbox and radio button
      if ($(this).is("label[for]")) {
        $(this)
          .off("keyup.setEaaForVisableObjects")
          .on("keyup.setEaaForVisableObjects", function (e) {
            if (e.keyCode == 13) {
              //enter key
              $("#" + $(this).attr("for")).trigger("click");
            }
          });
      }
      //on off button
      if ($(this).is(".button.button-off, .button.button-on")) {
        $(this)
          .off("keyup.setEaaForVisableObjects")
          .on("keyup.setEaaForVisableObjects", function (e) {
            if (e.keyCode == 13) {
              //enter key
              $(this).trigger("click");
            }
          });
      }
      //mobile-cancel-popup
      if ($(this).is(".mobile-cancel-popup")) {
        $(this)
          .off("keyup.setEaaForVisableObjects")
          .on("keyup.setEaaForVisableObjects", function (e) {
            if (e.keyCode == 13) {
              //enter key
              $(this).trigger("click");
            }
          });
      }
      //end event for enter key
    } else {
      $(this).removeAttr("tabindex");
      $(this).removeAttr("aria-label");
    }
  });
}

function announceEaaMsg(objs_msg, obj_announce) {
  // Collect all visible error messages
  let errorMessages = [];
  $(objs_msg).each(function () {
    errorMessages.push($(this).text().trim());
  });
  // Announce the errors
  let errorText = errorMessages.join(". ");
  $(obj_announce).text(errorText); // Announce errors
}

var eaa_isAnnouncingAction = false;
function eaa_set_isAnnouncingAction(bool_isAnnouncing) {
  eaa_isAnnouncingAction = bool_isAnnouncing;
}

function eaa_announceAction(str, options) {
  if (eaa_isAnnouncingAction) {
    $("#announcement").text(str);
    $("#announcement").attr({
      "aria-live": options
        ? options["aria-live"]
          ? options["aria-live"]
          : "assertive"
        : "assertive",
      role: options ? (options["role"] ? options["role"] : "alert") : "alert",
    });
  }
}

function eaa_announceOnOffButtonState(btn) {
  if ($(btn).is(".button-off")) {
    strStatus = getHTMLString("PAGE_STATUS_OFF");
  } else {
    strStatus = getHTMLString("PAGE_STATUS_ON");
  }
  var strTemp = getHTMLString("NOW_STATE");
  var str = strTemp.replace("[STATE]", strStatus);
  eaa_announceAction(str);
}

function eaa_announceCheckboxState(btn) {
  if ($(btn).is(".checkbox-checked")) {
    strStatus = getHTMLString("CHECKED");
  } else {
    strStatus = getHTMLString("UNCHECKED");
  }
  var strTemp = getHTMLString("NOW_STATE");
  var str = strTemp.replace("[STATE]", strStatus);
  eaa_announceAction(str);
}

function eaa_loopTabKey(context) {
  $("*[tabindex=0]:visible", context)
    .last()
    .off("keydown.eaaLoopTabKey")
    .on("keydown.eaaLoopTabKey", function (e) {
      //console.log('*[tabindex=0]:visible keydown');
      if (
        e.which == 9 // ||     // tab
        //e.which == 16 ||    // shift
        //e.which == 37 ||    // left arrow <-
        //e.which == 38 ||    // up arrow
        //e.which == 39 ||    // right arrow
        //e.which == 40       // down arrow
      ) {
        //console.log(e);
        $("*[tabindex=0]:visible", context).first().focus();

        return false;
      }
    });
}
//add end

//Validation
function inputFormateValidateion(val) {
  //if(val == "") return false;

  var rege = /[&'"//\\\[\]\{\}\(\):;|=,+*?<>]/;
  if (rege.test(val)) return false;
  else return true;
}

function inputNotEmptyFormate2Validateion(val) {
  if (val == "") return false;

  var rege = /[&'"//\\\[\]\{\}\(\);|=,+*?<>]/;
  if (rege.test(val)) return false;
  else return true;
}

function inputNotEmptyFormateValidateion(val) {
  if (val == "") return false;

  var rege = /[&'"//\\\[\]\{\}\(\):;|=,+*?<>]/;
  if (rege.test(val)) return false;
  else return true;
}

function timeFormateValidateion(time) {
  // check colum in between
  timeAry = time.split(":");
  if (timeAry.length != 2) return false;

  // check both are integers
  if (isNaN(timeAry[0])) return false;
  if (isNaN(timeAry[1])) return false;

  var hour = parseInt(timeAry[0]);
  var min = parseInt(timeAry[1]);
  // check if hour field in right range
  if (hour < 0 || hour > 23) return false;
  // check if the min field in right range
  if (min < 0 || min > 59) return false;

  // check passed
  return true;
}

function phoneFormateValidateion(val) {
  if (/^\+?\d+$/.test(val)) return true;
  else return false;
}

function Ascii32to126Validateion(val) {
  //scm_ascii_32to126 (0x20-0x7E)
  if (/^[\x20-\x7E]*$/.test(val)) return true;
  else return false;
}

function spaceNotBeginTerminateValidateion(val) {
  console.log("spaceNotBeginTerminateValidateion");
  //scm_space_not_in_begin_or_terminate
  if (/^ /.test(val)) {
    console.log("has space in begin");
    return false;
  } else if (/ $/.test(val)) {
    console.log("has space in terminate");
    return false;
  } else {
    console.log("NO space in begin or terminate");
    return true;
  }
}

function ipv4FormateValidateion(val) {
  if (val == "") return false;

  if (val.length <= 3) {
    if (/^[0-9]*$/.test(val)) {
      var tmp_val = parseInt(val, 10);
      if (tmp_val <= 255 && tmp_val >= 0) {
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  } else {
    return false;
  }
}

function macSegmentormateValidateion(val) {
  if (val == "" || val.length < 2) return false;

  var rege = /[0-9a-fA-F]+$/;
  if (rege.test(val[0]) && rege.test(val[1])) return true;
  else return false;
}

function macStringValidateion(val) {
  if (val == "") return true;
  var rege =
    /[A-F\d]{2}:[A-F\d]{2}:[A-F\d]{2}:[A-F\d]{2}:[A-F\d]{2}:[A-F\d]{2}/;
  if (rege.test(val)) return true;
  else return false;
}

function numberFormateValidateion(val) {
  if (val == "") return true;

  if (/^\d+$/.test(val)) {
    var tmp_val = parseInt(val, 10);
    if (tmp_val <= 0) return false;
    else return true;
  } else return false;
}

function numberNotEmptyFormateValidateion(val) {
  if (/^\d+$/.test(val)) {
    var tmp_val = parseInt(val, 10);
    if (tmp_val <= 0) return false;
    else return true;
  } else return false;
}

function signedINTFormateValidateion(val) {
  if (val == "") return false;

  if (/^-?\d+$/.test(val)) return true;
  else return false;
}

function unsignedINTFormateValidateion(val) {
  if (val == "") return false;

  if (/^\d+$/.test(val)) return true;
  else return false;
}

function portFormateValidateion(val) {
  if (val == "") return false;

  if (/\d+$/.test(val)) {
    var tmp_val = parseInt(val, 10);
    if (tmp_val < 1 || tmp_val > 65535) return false;
    else return true;
  } else return false;
}

function dscpFormateValidateion(val) {
  if (val == "") return false;

  if (/\d+$/.test(val)) {
    var tmp_val = parseInt(val, 10);
    if (tmp_val < 0 || tmp_val > 63) return false;
    else return true;
  } else return false;
}

function rateFormateValidateion(val) {
  if (val == "") return false;

  if (/\d+$/.test(val)) {
    var tmp_val = parseInt(val, 10);
    if (tmp_val < -1 || tmp_val > 1250000) return false;
    else return true;
  } else return false;
}

function timeRangeValidation(timeA, timeB) {
  if (timeToMin(timeB) < timeToMin(timeA)) return false;
  return true;
}

function timeRangeInterfierValidation(
  rangeAstart,
  rangeAend,
  rangeBstart,
  rangeBend,
) {
  rangeAstartMin = timeToMin(rangeAstart);
  rangeAendMin = timeToMin(rangeAend) - 1;
  rangeBstartMin = timeToMin(rangeBstart);
  rangeBendMin = timeToMin(rangeBend) - 1;

  if (rangeBstartMin >= rangeAstartMin && rangeBstartMin <= rangeAendMin)
    return false;
  if (rangeBendMin >= rangeAstartMin && rangeBendMin <= rangeAendMin)
    return false;

  if (rangeBstartMin < rangeAstartMin && rangeBendMin > rangeAendMin)
    return false;
  if (rangeAstartMin < rangeBstartMin && rangeAendMin > rangeBendMin)
    return false;

  return true;
}

function timeInterfierValidation(timeA, timeB) {
  timeAmin = timeToMin(timeA);
  timeBmin = timeToMin(timeB);
  if (timeAmin == timeBmin) return false;

  return true;
}

function timeToMin(inTime) {
  timeAry = inTime.split(":");
  var min = parseInt(timeAry[0] * 60 + parseInt(timeAry[1]));
  return min;
}

function maxLengthValidateion(val, len) {
  if (!basicFormateValidation(val)) return false;

  if (val.length <= len) return true;
  else return false;
}

function minLengthValidateion(val, len) {
  if (!basicFormateValidation(val)) return false;

  if (val.length >= len) return true;
  else return false;
}

function maxNumberValidateion(val, number) {
  if (parseInt(val, 10) <= parseInt(number, 10)) return true;
  else return false;
}

function minNumberValidateion(val, number) {
  if (parseInt(val, 10) >= parseInt(number, 10)) return true;
  else return false;
}

function ipv6SubnetIdValidateion(val, param) {
  var allowEmpty = false;
  var allowColon = false;

  var paramlist = param.split(",");
  for (var x in paramlist) {
    var one = paramlist[x].trim();
    if (one == "allowEmpty") allowEmpty = true;
    else if (one == "allowColon") allowColon = true;
  }

  if (val.length <= 0) {
    if (allowEmpty) return true;
    else return false;
  }

  var rege = /[^0-9a-fA-F]/;
  if (allowColon) rege = /[^0-9a-fA-F:]/;
  if (rege.test(val)) return false;
  else return true;
}

function domainFormateValidateion(val) {
  var tmp_val = val.split(".");
  if (tmp_val.length < 2) return false;
  var rege =
    /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(?!-)(?!:\/\/)(?=.{1,255}$)(([-a-z0-9]{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$/i;
  if (rege.test(val)) return true;
  else {
    return false;
  }
}

function emailFormateValidateion(val) {
  var tmp_val = val.split("@");
  if (tmp_val.length != 2) return false;

  var rege =
    /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  if (rege.test(val)) return true;
  else return false;
}

function ip4ip6FormateValidation(val) {
  var rege =
    /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/;
  if (rege.test(val)) return true;
  else return false;
}

function basicFormateValidation(val) {
  var rege = /['"\\<>]/;
  if (rege.test(val)) {
    return false;
  } else {
    var testdata = val.toLowerCase();
    var rege1 = new RegExp("&lt");
    var rege2 = new RegExp("&gt");
    var rege3 = new RegExp("&#");
    if (rege1.test(testdata) || rege2.test(testdata) || rege3.test(testdata)) {
      return false;
    } else {
      return true;
    }
  }
}

function ploampasswdFormateValidation(val) {
  if (val.length <= 10) {
    return true;
  } else if (val.length == 20) {
    var rege = /^([0-9]|[a-f]|[A-F]){20}/;
    if (rege.test(val)) return true;
  } else {
    return false;
  }
}

function chkInputTextValidation(obj) {
  var ret_val = true;
  $(obj).each(function () {
    $(this).removeClass("input-message-error");

    if (ret_val) {
      if ($(this).hasClass("scm_not_chk")) {
        //no need check
      } else if (
        $(this).hasClass("scm_can_empty") &&
        $(this).val().length == 0
      ) {
      } else {
        var not_checked = true;
        //time format
        if ($(this).hasClass("scm_time")) {
          not_checked = false;

          if (!timeFormateValidateion($(this).val())) ret_val = false;
        }
        //phone format
        if ($(this).hasClass("scm_phone")) {
          not_checked = false;

          if (!phoneFormateValidateion($(this).val())) ret_val = false;
        }
        //ipv4
        if ($(this).hasClass("scm_ip4")) {
          not_checked = false;

          if (!ipv4FormateValidateion($(this).val())) ret_val = false;
        }
        //ipv4 and empty
        if ($(this).hasClass("scm_ip4_and_empty")) {
          not_checked = false;
          if ($(this).val() !== "") {
            if (!ipv4FormateValidateion($(this).val())) ret_val = false;
          }
        }
        //mac segment
        if ($(this).hasClass("scm_mac_segment")) {
          not_checked = false;

          $(this).val($(this).val().toUpperCase());
          if (!macSegmentormateValidateion($(this).val())) ret_val = false;
        }
        //mac string
        if ($(this).hasClass("scm_mac_string")) {
          not_checked = false;

          $(this).val($(this).val().toUpperCase());
          if (!macStringValidateion($(this).val())) ret_val = false;
        }
        //number
        if ($(this).hasClass("scm_num")) {
          not_checked = false;

          if (!numberFormateValidateion($(this).val())) {
            ret_val = false;
          } else {
            $(this).val(parseInt($(this).val(), 10));
          }
        }
        //port
        if ($(this).hasClass("scm_port")) {
          not_checked = false;

          if (!portFormateValidateion($(this).val())) ret_val = false;
        }
        //rate limit
        if ($(this).hasClass("scm_rate")) {
          not_checked = false;

          if (!rateFormateValidateion($(this).val())) ret_val = false;
        }
        //dscp
        if ($(this).hasClass("scm_dscp_range")) {
          not_checked = false;

          if (!dscpFormateValidateion($(this).val())) ret_val = false;
        }

        //number not empty
        if ($(this).hasClass("scm_num_not_empty")) {
          not_checked = false;

          if (!numberNotEmptyFormateValidateion($(this).val())) {
            ret_val = false;
          } else {
            $(this).val(parseInt($(this).val(), 10));
          }
        }
        //signed int
        if ($(this).hasClass("scm_signed_int")) {
          not_checked = false;

          if (!signedINTFormateValidateion($(this).val())) {
            ret_val = false;
          } else {
            $(this).val(parseInt($(this).val(), 10));
          }
        }
        //unsigned int
        if ($(this).hasClass("scm_unsigned_int")) {
          not_checked = false;

          if (!unsignedINTFormateValidateion($(this).val())) {
            ret_val = false;
          } else {
            $(this).val(parseInt($(this).val(), 10));
          }
        }
        //max length
        if ($(this).hasClass("scm_max_length")) {
          not_checked = false;

          if (
            !maxLengthValidateion($(this).val(), $(this).attr("scm_max_length"))
          )
            ret_val = false;
        }
        //min length
        if ($(this).hasClass("scm_min_length")) {
          not_checked = false;

          if (
            !minLengthValidateion($(this).val(), $(this).attr("scm_min_length"))
          )
            ret_val = false;
        }
        //max number
        if ($(this).hasClass("scm_max_number")) {
          not_checked = false;

          if (
            !maxNumberValidateion($(this).val(), $(this).attr("scm_max_number"))
          )
            ret_val = false;
        }
        //min number
        if ($(this).hasClass("scm_min_number")) {
          not_checked = false;

          if (
            !minNumberValidateion($(this).val(), $(this).attr("scm_min_number"))
          )
            ret_val = false;
        }
        // ascii printable char 32(0x20)-126(0x7E)
        if ($(this).hasClass("scm_ascii_32to126")) {
          not_checked = false;

          if (
            !Ascii32to126Validateion(
              $(this).val(),
              $(this).attr("scm_ascii_32to126"),
            )
          )
            ret_val = false;
        }
        // scm_space_not_in_begin_or_terminate
        if ($(this).hasClass("scm_space_not_in_begin_or_terminate")) {
          not_checked = false;

          if (
            !spaceNotBeginTerminateValidateion(
              $(this).val(),
              $(this).attr("scm_space_not_in_begin_or_terminate"),
            )
          )
            ret_val = false;
        }

        //domain
        if ($(this).hasClass("scm_domain")) {
          not_checked = false;

          if (!domainFormateValidateion($(this).val())) ret_val = false;
        }
        //email
        if ($(this).hasClass("scm_email")) {
          not_checked = false;

          if (!emailFormateValidateion($(this).val())) ret_val = false;
        }
        //IPv4 IPv6
        if ($(this).hasClass("scm_ip4ip6")) {
          not_checked = false;

          if (!ip4ip6FormateValidation($(this).val())) ret_val = false;
        }
        //basic
        if ($(this).hasClass("scm_basic_valid")) {
          not_checked = false;

          if (!basicFormateValidation($(this).val())) ret_val = false;
        }
        //not empty
        if ($(this).hasClass("scm_not_empty")) {
          not_checked = false;

          if (!inputNotEmptyFormateValidateion($(this).val())) ret_val = false;
        }
        //scm_not_empty2
        if ($(this).hasClass("scm_not_empty2")) {
          not_checked = false;

          if (!inputNotEmptyFormate2Validateion($(this).val())) ret_val = false;
        }
        //ploam password check
        if ($(this).hasClass("scm_ploam_pwd")) {
          not_checked = false;

          if (!ploampasswdFormateValidation($(this).val())) ret_val = false;
        }
        //ipv6 subnet-ID check
        if ($(this).hasClass("scm_ipv6_subnet_id")) {
          not_checked = false;

          if (
            !ipv6SubnetIdValidateion(
              $(this).val(),
              $(this).attr("scm_ipv6_subnet_id"),
            )
          )
            ret_val = false;
        }

        if (not_checked) {
          if (!inputFormateValidateion($(this).val())) ret_val = false;
        }
      }

      if (!ret_val) {
        $(this).addClass("input-message-error");
      }
    }
  });

  return ret_val;
}

function OnOffButton_setValue(obj, value) {
  if (value == "1") {
    obj.removeClass("button-off").addClass("button-on");
  } else {
    obj.removeClass("button-on").addClass("button-off");
  }
}

function OnOffButton_getValue(obj) {
  return obj.hasClass("button-on") ? "1" : "0";
}

function pushElementToArrayIfObjExists(obj, arr, elt) {
  if (obj.length > 0) {
    arr.push(elt);
  }
}

function byteCount(s) {
  //This function will return the byte size of any UTF-8 string you pass to it.

  return encodeURI(s).split(/%..|./).length - 1;
}

function net_IPnumber(IPaddress) {
  var ip = IPaddress.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ip) {
    return (+ip[1] << 24) + (+ip[2] << 16) + (+ip[3] << 8) + +ip[4];
  }
  // else ... ?
  return null;
}

function net_IPmask(maskSize) {
  return -1 << (32 - maskSize);
}

function net_inSubNet(ip, subnet) {
  // ip: '123.123.49.123', subnet: '123.123.48.0/22'  => true
  // ip: '123.123.49.123', subnet: '123.123.48.1/22'  => true
  // ip: '123.123.52.123', subnet: '123.123.48.0/22'  => false

  // (IPnumber('123.123.49.123') & IPmask('22')) == IPnumber('123.123.48.0')  => true
  var mask, base_ip, maskSize;
  mask = subnet.match(/^(.*?)\/(\d{1,2})$/);
  base_ip = mask[1];
  maskSize = mask[2];
  //console.log((subnet_IPnumber(ip) & subnet_IPmask(maskSize)).toString(2));
  //console.log((subnet_IPnumber(base_ip) & subnet_IPmask(maskSize)).toString(2));

  return (
    (net_IPnumber(ip) & net_IPmask(maskSize)) ==
    (net_IPnumber(base_ip) & net_IPmask(maskSize))
  );
}

function net_isIpInRangeSubnetArray(ipTest, subNetArray) {
  for (var key in subNetArray) {
    if (subNetArray[key] !== "") {
      var one_subnet = subNetArray[key];
      var rtest = net_inSubNet(ipTest, one_subnet);
      if (rtest) {
        return rtest;
      }
    }
  }
  return false;
}

function net_cidrMask(subnetMask) {
  mask = subnetMask.split(".");
  if (mask.length != 4) {
    throw "Precondition failed: subnet mask should only have four octets!";
  }

  bits = 0;
  for (var i = 0; i < mask.length; i += 1) {
    octet = parseInt(mask[i]);
    if (octet > 255 || octet < 0) {
      throw "Precondition failed: octet out of range!";
    }
    while (octet > 0) {
      bits += octet % 2;
      octet = octet >> 1;
    }
  }

  if (bits > 32) {
    throw "Postcondition failed: Too many bits!";
  }
  return bits;
}

function net_inSubNet_by_serverIpAndMask(ip, ipServer, ipServerMask) {
  // ip: '192.168.122.2', ipServer: '192.168.123.1', ipServerMask: 255.255.252.0(22)   => true
  var base_ip, maskSize;
  base_ip = ipServer;
  maskSize = net_cidrMask(ipServerMask);
  //console.log(base_ip + '/' + maskSize);

  return (
    (net_IPnumber(ip) & net_IPmask(maskSize)) ==
    (net_IPnumber(base_ip) & net_IPmask(maskSize))
  );
}

function net_ip_findNetworkIPAddressClass(ipStr) {
  var ip_ary = ipStr.split(".");
  var ip = parseInt(ip_ary[0], 10);
  // Class A
  if (ip >= 1 && ip <= 126) return "A";
  // Class B
  else if (ip >= 128 && ip <= 191) return "B";
  // Class C
  else if (ip >= 192 && ip < 223) return "C";
  // Class D
  else if (ip >= 224 && ip <= 239) return "D";
  // Class E
  else return "E";
}
