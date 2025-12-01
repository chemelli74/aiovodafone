var sys_type = "VD"; //1:(AD_SP)AD1018 spain, 2:(AD_INT)AD1018 internetional, 3:(FD)FD1018, 4:(VD)VD1018

function _obj_navigation_basic() {
  if (sys_region_code == "sp_else") {
    var navigation = [
      //phone
      {
        tab: "phone",
        id: "call-log",
        hashid: "7",
        langid: "902001",
        control: [],
        submenu: [],
      }, //Call Log
      //internet
      {
        tab: "internet",
        id: "umts",
        hashid: "89",
        langid: "SUB_NAVIGATION_ITEM_MOBILE",
        control: ["sys_umts_status", "show_internet_mobile"],
        submenu: [],
      }, //UMTS
      //wifi
      {
        tab: "wifi",
        id: "general",
        hashid: "35",
        langid: "904001",
        control: [],
        submenu: [],
      }, //General
      {
        tab: "wifi",
        id: "schedule",
        hashid: "36",
        langid: "PAGE_SCHEDULE_TITLE",
        control: [],
        submenu: [],
      }, //Power Saving Mode
      {
        tab: "wifi",
        id: "wps",
        hashid: "37",
        langid: "904003",
        control: [],
        submenu: [
          //WPS
        ],
      },
      {
        tab: "wifi",
        id: "band_steering",
        hashid: "band_steering",
        langid: "PAGE_BAND_STEERING_TITLE",
        control: ["sys_band_steering", "show_wifi_bandsteering"],
        submenu: [],
      }, //Band Steering
      /*
        //messages
		{tab:'messages', id:'content-create_message', hashid:'create_message', langid:'SUB_NAVIGATION_ITEM_CREATE_MESSAGE', control:[], submenu:[]}, //Create Message
		{tab:'messages', id:'content-inbox', hashid:'inbox', langid:'SUB_NAVIGATION_ITEM_INBOX', control:[], submenu:[]}, //Inbox
		{tab:'messages', id:'content-sent', hashid:'sent', langid:'SUB_NAVIGATION_ITEM_SENT', control:[], submenu:[]}, //Sent
		{tab:'messages', id:'content-outbox', hashid:'outbox', langid:'SUB_NAVIGATION_ITEM_OUTBOX', control:[], submenu:[]}, //Outbox
		*/
      //settings
      {
        tab: "settings",
        id: "password",
        hashid: "60",
        langid: "905001",
        control: [],
        submenu: [],
      }, //Password
      {
        tab: "settings",
        id: "energy-settings",
        hashid: "55",
        langid: "PAGE_ENERGY_SETTINGS_TITLE",
        control: ["show_settings_energysettings"],
        submenu: [],
      }, //Energy Settings
      {
        tab: "settings",
        id: "content-sharing",
        hashid: "56",
        langid: "SUB_NAVIGATION_ITEM_CONTENT_SHARING",
        control: ["sys_usb_status"],
        submenu: [
          //Content Sharing
          {
            tab: "settings",
            id: "dlna",
            hashid: "57",
            langid: "905004",
            control: ["sys_usb_status"],
            submenu: [],
          }, //DLNA
        ],
      },
      {
        tab: "settings",
        id: "configuration",
        hashid: "54",
        langid: "905007",
        control: [],
        submenu: [],
      }, //Configuration
      //status-and-support
      {
        tab: "status-and-support",
        id: "status",
        hashid: "1",
        langid: "906001",
        control: [],
        submenu: [
          //Status
          {
            tab: "status-and-support",
            id: "voice_status",
            hashid: "3",
            langid: "906003",
            control: [],
            submenu: [],
          }, //, //Voice Status
        ],
      },
      {
        tab: "status-and-support",
        id: "diagnostic-utility",
        hashid: "4",
        langid: "906004",
        control: [],
        submenu: [
          //Diagnostic Utility
        ],
      },
      //{tab:'status-and-support', id:'event-log', hashid:'6', langid:'906006', control:[], submenu:[]}, //Event Log
      {
        tab: "status-and-support",
        id: "restart",
        hashid: "41",
        langid: "906007",
        control: [],
        submenu: [],
      }, //Restart
      //{tab:'status-and-support', id:'nat-mapping-table', hashid:'28', langid:'903007', control:[], submenu:[]}, //NAT Mapping Table
      {
        tab: "status-and-support",
        id: "about",
        hashid: "42",
        langid: "906008",
        control: [],
        submenu: [],
      }, //About
    ];

    return navigation;
  } else if (sys_region_code == "cz_else") {
    var navigation = [
      //internet
      {
        tab: "internet",
        id: "firewall",
        hashid: "22",
        langid: "903001",
        control: [],
        submenu: [],
      }, //Firewall

      //wifi
      {
        tab: "wifi",
        id: "general",
        hashid: "35",
        langid: "904001",
        control: ["sys_router_mode"],
        submenu: [],
      }, //General
      {
        tab: "wifi",
        id: "schedule",
        hashid: "36",
        langid: "PAGE_SCHEDULE_TITLE",
        control: ["sys_router_mode"],
        submenu: [],
      }, //Power Saving Mode
      {
        tab: "wifi",
        id: "wps",
        hashid: "37",
        langid: "904003",
        control: ["sys_router_mode"],
        submenu: [],
      }, //WPS
      {
        tab: "wifi",
        id: "band_steering",
        hashid: "band_steering",
        langid: "PAGE_BAND_STEERING_TITLE",
        control: [
          "sys_router_mode",
          "sys_band_steering",
          "show_wifi_bandsteering",
        ],
        submenu: [],
      }, //Band Steering

      //settings
      {
        tab: "settings",
        id: "password",
        hashid: "60",
        langid: "905001",
        control: [],
        submenu: [],
      }, //Password
      {
        tab: "settings",
        id: "energy-settings",
        hashid: "55",
        langid: "PAGE_ENERGY_SETTINGS_TITLE",
        control: ["show_settings_energysettings"],
        submenu: [],
      }, //Energy Settings
      {
        tab: "settings",
        id: "content-sharing",
        hashid: "56",
        langid: "SUB_NAVIGATION_ITEM_CONTENT_SHARING",
        control: ["sys_usb_status"],
        submenu: [
          //Content Sharing
          {
            tab: "settings",
            id: "dlna",
            hashid: "57",
            langid: "905004",
            control: ["sys_usb_status"],
            submenu: [],
          }, //DLNA
        ],
      },
      {
        tab: "settings",
        id: "configuration",
        hashid: "54",
        langid: "905007",
        control: [],
        submenu: [],
      }, //Configuration
      {
        tab: "settings",
        id: "sfp-reg-id",
        hashid: "sfp-reg-id",
        langid: "SUB_NAVIGATION_ITEM_SFP_REG_ID",
        control: ["sys_sfp_status"],
        submenu: [],
      }, //SFP REG ID
      //{tab:'settings', id:'openmodem_internet_time', hashid:'openmodem_internet_time', langid:'513001', control:["sys_openmodem_status","sys_openmodem_subpages_status"], submenu:[]}, //Internet Time
      {
        tab: "settings",
        id: "internet-time",
        hashid: "74",
        langid: "513001",
        control: [],
        submenu: [],
      }, //Internet Time
      {
        tab: "settings",
        id: "modem-mode",
        hashid: "modem-mode",
        langid: "PAGE_MODEM_MODE_TITLE",
        control: [],
        submenu: [],
      }, //modem-mode

      //status-and-support
      {
        tab: "status-and-support",
        id: "status",
        hashid: "1",
        langid: "906001",
        control: [],
        submenu: [
          //Status
          {
            tab: "status-and-support",
            id: "gpon_status",
            hashid: "gpon_status",
            langid: "1301761",
            control: [],
            submenu: [],
          }, //GPON Status
          {
            tab: "status-and-support",
            id: "vdsl_status",
            hashid: "66",
            langid: "1300081",
            control: ["show_ss_vdsl"],
            submenu: [],
          }, //VDSL Status
          {
            tab: "status-and-support",
            id: "fibre_status",
            hashid: "82",
            langid: "907003",
            control: ["show_ss_fibre"],
            submenu: [],
          }, //Fibre Statuss
          {
            tab: "status-and-support",
            id: "wan_status",
            hashid: "67",
            langid: "906013",
            control: [],
            submenu: [],
          }, //WAN Status
          {
            tab: "status-and-support",
            id: "optical_status",
            hashid: "201",
            langid: "1301726",
            control: [],
            submenu: [],
          }, //Optical Status
          {
            tab: "status-and-support",
            id: "lan_status",
            hashid: "70",
            langid: "906014",
            control: [],
            submenu: [],
          }, //LAN Status
          {
            tab: "status-and-support",
            id: "routing_status",
            hashid: "71",
            langid: "906015",
            control: [],
            submenu: [],
          }, //Routing
          {
            tab: "status-and-support",
            id: "umts_status",
            hashid: "44",
            langid: "1301451",
            control: ["sys_umts_status", "show_ss_mobile"],
            submenu: [],
          }, //Mobile Status
        ],
      },
      {
        tab: "status-and-support",
        id: "diagnostic-utility",
        hashid: "4",
        langid: "906004",
        control: [],
        submenu: [],
      }, //Diagnostic Utility
      {
        tab: "status-and-support",
        id: "restart",
        hashid: "41",
        langid: "906007",
        control: [],
        submenu: [],
      }, //Restart
      {
        tab: "status-and-support",
        id: "about",
        hashid: "42",
        langid: "906008",
        control: [],
        submenu: [],
      }, //About
    ];

    return navigation;
  } else {
    var navigation = [
      //phone
      {
        tab: "phone",
        id: "call-log",
        hashid: "7",
        langid: "902001",
        control: [],
        submenu: [],
      }, //Call Log
      //internet
      {
        tab: "internet",
        id: "umts",
        hashid: "89",
        langid: "SUB_NAVIGATION_ITEM_MOBILE",
        control: ["sys_umts_status", "show_internet_mobile"],
        submenu: [],
      }, //UMTS
      {
        tab: "internet",
        id: "firewall",
        hashid: "22",
        langid: "903001",
        control: [],
        submenu: [],
      }, //Firewall
      //{tab:'internet', id:'dns', hashid:'dns', langid:'SUB_NAVIGATION_ITEM_DNS', control:[], submenu:[]}, //DNS
      //{tab:'internet', id:'ddns', hashid:'29', langid:'SUB_NAVIGATION_ITEM_DDNS', control:[], submenu:[]}, //DDNS

      //wifi
      {
        tab: "wifi",
        id: "general",
        hashid: "35",
        langid: "904001",
        control: [],
        submenu: [],
      }, //General
      {
        tab: "wifi",
        id: "schedule",
        hashid: "36",
        langid: "PAGE_SCHEDULE_TITLE",
        control: [],
        submenu: [],
      }, //Power Saving Mode
      {
        tab: "wifi",
        id: "wps",
        hashid: "37",
        langid: "904003",
        control: [],
        submenu: [
          //WPS
          {
            tab: "wifi",
            id: "pairing-smart-app",
            hashid: "pairing-smart-app",
            langid: "SUB_NAVIGATION_ITEM_WPS_PAIRING",
            control: ["sys_smartapp_status"],
            submenu: [],
          }, //Pairing Smart App
        ],
      },
      {
        tab: "wifi",
        id: "band_steering",
        hashid: "band_steering",
        langid: "PAGE_BAND_STEERING_TITLE",
        control: ["sys_band_steering", "show_wifi_bandsteering"],
        submenu: [],
      }, //Band Steering
      /*
		//messages
		{tab:'messages', id:'content-create_message', hashid:'create_message', langid:'SUB_NAVIGATION_ITEM_CREATE_MESSAGE', control:[], submenu:[]}, //Create Message
		{tab:'messages', id:'content-inbox', hashid:'inbox', langid:'SUB_NAVIGATION_ITEM_INBOX', control:[], submenu:[]}, //Inbox
		{tab:'messages', id:'content-sent', hashid:'sent', langid:'SUB_NAVIGATION_ITEM_SENT', control:[], submenu:[]}, //Sent
		{tab:'messages', id:'content-outbox', hashid:'outbox', langid:'SUB_NAVIGATION_ITEM_OUTBOX', control:[], submenu:[]}, //Outbox
    */
      //settings
      {
        tab: "settings",
        id: "password",
        hashid: "60",
        langid: "905001",
        control: [],
        submenu: [],
      }, //Password
      {
        tab: "settings",
        id: "vodafone_safe_netwok",
        hashid: "vodafone_safe_netwok",
        langid: "SUB_NAVIGATION_ITEM_VODAFONE_SAFE_NETWORK",
        control: ["sys_vodafone_safe_netwok"],
        submenu: [],
      }, //Safe Network
      {
        tab: "settings",
        id: "energy-settings",
        hashid: "55",
        langid: "PAGE_ENERGY_SETTINGS_TITLE",
        control: ["show_settings_energysettings"],
        submenu: [],
      }, //Energy Settings
      {
        tab: "settings",
        id: "content-sharing",
        hashid: "56",
        langid: "SUB_NAVIGATION_ITEM_CONTENT_SHARING",
        control: ["sys_usb_status"],
        submenu: [
          //Content Sharing
          {
            tab: "settings",
            id: "dlna",
            hashid: "57",
            langid: "905004",
            control: ["sys_usb_status"],
            submenu: [],
          }, //DLNA
        ],
      },
      {
        tab: "settings",
        id: "configuration",
        hashid: "54",
        langid: "905007",
        control: [],
        submenu: [],
      }, //Configuration
      {
        tab: "settings",
        id: "sfp-reg-id",
        hashid: "sfp-reg-id",
        langid: "SUB_NAVIGATION_ITEM_SFP_REG_ID",
        control: ["sys_sfp_status"],
        submenu: [],
      }, //SFP REG ID
      //status-and-support
      {
        tab: "status-and-support",
        id: "status",
        hashid: "1",
        langid: "906001",
        control: [],
        submenu: [
          //Status
          {
            tab: "status-and-support",
            id: "voice_status",
            hashid: "3",
            langid: "906003",
            control: [],
            submenu: [],
          }, //Voice Status
          {
            tab: "status-and-support",
            id: "gpon_status",
            hashid: "gpon_status",
            langid: "1301761",
            control: [],
            submenu: [],
          }, //GPON Status
          {
            tab: "status-and-support",
            id: "dongle-connectivity",
            hashid: "dongle-connectivity",
            langid: "SUB_SUB_NAVIGATION_ITEM_DONGLE_CONNECTIVITY",
            control: ["sys_umts_status"],
            submenu: [],
          }, //Dongle Connectivity
        ],
      },
      {
        tab: "status-and-support",
        id: "diagnostic-utility",
        hashid: "4",
        langid: "906004",
        control: [],
        submenu: [],
      }, //Diagnostic Utility
      {
        tab: "status-and-support",
        id: "restart",
        hashid: "41",
        langid: "906007",
        control: [],
        submenu: [],
      }, //Restart
      {
        tab: "status-and-support",
        id: "about",
        hashid: "42",
        langid: "906008",
        control: [],
        submenu: [],
      }, //About
    ];

    return navigation;
  }
}

function _obj_navigation_expert() {
  if (sys_region_code == "sp_else") {
    var navigation = [
      //phone
      {
        tab: "phone",
        id: "call-settings",
        hashid: "79",
        langid: "SUB_SUB_NAVIGATION_ITEM_PHONE_SETTINGS",
        control: [],
        submenu: [],
      }, //Call Settings
      {
        tab: "phone",
        id: "phone-numbers",
        hashid: "17",
        langid: "902011",
        control: [],
        submenu: [
          //Phone Numbers
          //{tab:'phone', id:'number-setting', hashid:'numbersettings', langid:'SUB_NAVIGATION_ITEM_PHONE_SETTINGS', control:[], submenu:[]} //Phone Settings
        ],
      },
      {
        tab: "phone",
        id: "call-log",
        hashid: "7",
        langid: "902001",
        control: [],
        submenu: [],
      }, //Call Log
      {
        tab: "phone",
        id: "ringing-schedule",
        hashid: "16",
        langid: "902010",
        control: ["show_phone_ringschedule"],
        submenu: [],
      }, //Ringing Schedule
      //internet
      /*
		{tab:'internet', id:'firewall', hashid:'22', langid:'903001', control:[], submenu:[ //Firewall
			{tab:'internet', id:'content-dos', hashid:'content-dos', langid:'1310012', control:[], submenu:[]}//, //DoS
			//{tab:'internet', id:'content-access-control-list', hashid:'content-access-control-list', langid:'PAGE_ACCESS_CONTROL_LIST_TITLE', control:[], submenu:[]} //Access Control List
		]},
        */
      {
        tab: "internet",
        id: "umts",
        hashid: "89",
        langid: "SUB_NAVIGATION_ITEM_MOBILE",
        control: ["sys_umts_status", "show_internet_mobile"],
        submenu: [],
      }, //UMTS
      {
        tab: "internet",
        id: "port-mapping",
        hashid: "26",
        langid: "903005",
        control: [],
        submenu: [],
      }, //Port Mapping
      {
        tab: "internet",
        id: "exposed-host",
        hashid: "27",
        langid: "903006",
        control: [],
        submenu: [],
      }, //DMZ
      {
        tab: "internet",
        id: "parental-control",
        hashid: "23",
        langid: "PAGE_PAGE_PARENTAL_CONTROL_TITLE",
        control: [],
        submenu: [],
      }, //Parental Control
      {
        tab: "internet",
        id: "dns",
        hashid: "dns",
        langid: "SUB_NAVIGATION_ITEM_DNS",
        control: [],
        submenu: [],
      }, //DNS
      {
        tab: "internet",
        id: "ddns",
        hashid: "29",
        langid: "SUB_NAVIGATION_ITEM_DDNS",
        control: [],
        submenu: [],
      }, //DDNS
      {
        tab: "internet",
        id: "wolan",
        hashid: "wolan",
        langid: "PAGE_WOLAN_TITLE",
        control: ["show_internet_wolan"],
        submenu: [],
      }, //WoLAN
      //wifi
      {
        tab: "wifi",
        id: "general",
        hashid: "35",
        langid: "904001",
        control: [],
        submenu: [],
      }, //General
      {
        tab: "wifi",
        id: "schedule",
        hashid: "36",
        langid: "PAGE_SCHEDULE_TITLE",
        control: [],
        submenu: [],
      }, //Power Saving Mode
      {
        tab: "wifi",
        id: "wps",
        hashid: "37",
        langid: "904003",
        control: [],
        submenu: [
          //WPS
          //{tab:'wifi', id:'pairing-smart-app', hashid:'pairing-smart-app', langid:'SUB_NAVIGATION_ITEM_WPS_PAIRING', control:["sys_smartapp_status"], submenu:[]} //Pairing Smart App
        ],
      },
      {
        tab: "wifi",
        id: "mac-filter",
        hashid: "38",
        langid: "904004",
        control: [],
        submenu: [],
      }, //MAC Filter
      {
        tab: "wifi",
        id: "band_steering",
        hashid: "band_steering",
        langid: "PAGE_BAND_STEERING_TITLE",
        control: ["sys_band_steering", "show_wifi_bandsteering"],
        submenu: [],
      }, //Band Steering
      /*
        //messages
		{tab:'messages', id:'content-create_message', hashid:'create_message', langid:'SUB_NAVIGATION_ITEM_CREATE_MESSAGE', control:[], submenu:[]}, //Create Message
		{tab:'messages', id:'content-inbox', hashid:'inbox', langid:'SUB_NAVIGATION_ITEM_INBOX', control:[], submenu:[]}, //Inbox
		{tab:'messages', id:'content-sent', hashid:'sent', langid:'SUB_NAVIGATION_ITEM_SENT', control:[], submenu:[]}, //Sent
		{tab:'messages', id:'content-outbox', hashid:'outbox', langid:'SUB_NAVIGATION_ITEM_OUTBOX', control:[], submenu:[]}, //Outbox
		*/
      //settings
      {
        tab: "settings",
        id: "password",
        hashid: "60",
        langid: "905001",
        control: [],
        submenu: [],
      }, //Password
      {
        tab: "settings",
        id: "energy-settings",
        hashid: "55",
        langid: "PAGE_ENERGY_SETTINGS_TITLE",
        control: ["show_settings_energysettings"],
        submenu: [],
      }, //Energy Settings
      {
        tab: "settings",
        id: "usb",
        hashid: "58",
        langid: "905003",
        control: ["sys_usb_status"],
        submenu: [],
      }, //USB
      {
        tab: "settings",
        id: "content-sharing",
        hashid: "56",
        langid: "SUB_NAVIGATION_ITEM_CONTENT_SHARING",
        control: ["sys_usb_status"],
        submenu: [
          //Content Sharing
          {
            tab: "settings",
            id: "dlna",
            hashid: "57",
            langid: "905004",
            control: ["sys_usb_status"],
            submenu: [],
          }, //DLNA
          {
            tab: "settings",
            id: "network-share-samba",
            hashid: "51",
            langid: "SUB_SUB_NAVIGATION_ITEM_NETWORK_SHARE_SAMBA",
            control: ["sys_usb_status"],
            submenu: [],
          }, //Samba
          {
            tab: "settings",
            id: "ftp",
            hashid: "50",
            langid: "905011",
            control: ["sys_usb_status"],
            submenu: [],
          }, //FTP
          {
            tab: "settings",
            id: "upnp",
            hashid: "85",
            langid: "315001",
            control: ["sys_usb_status"],
            submenu: [],
          }, //UPnP
        ],
      },
      {
        tab: "settings",
        id: "printer-sharing",
        hashid: "83",
        langid: "521001",
        control: ["sys_usb_status", "show_settings_printersharing"],
        submenu: [],
      }, //Printer Sharing
      {
        tab: "settings",
        id: "configuration",
        hashid: "54",
        langid: "905007",
        control: [],
        submenu: [],
      }, //Configuration
      {
        tab: "settings",
        id: "lan",
        hashid: "52",
        langid: "905009",
        control: [],
        submenu: [],
      }, //LAN
      //status-and-support
      {
        tab: "status-and-support",
        id: "status",
        hashid: "1",
        langid: "906001",
        control: [],
        submenu: [
          //Status
          {
            tab: "status-and-support",
            id: "voice_status",
            hashid: "3",
            langid: "906003",
            control: [],
            submenu: [],
          }, //, //Voice Status
        ],
      },
      {
        tab: "status-and-support",
        id: "diagnostic-utility",
        hashid: "4",
        langid: "906004",
        control: [],
        submenu: [
          //Diagnostic Utility
        ],
      },
      //{tab:'status-and-support', id:'event-log', hashid:'6', langid:'906006', control:[], submenu:[]}, //Event Log
      {
        tab: "status-and-support",
        id: "restart",
        hashid: "41",
        langid: "906007",
        control: [],
        submenu: [],
      }, //Restart
      //{tab:'status-and-support', id:'nat-mapping-table', hashid:'28', langid:'903007', control:[], submenu:[]}, //NAT Mapping Table
      {
        tab: "status-and-support",
        id: "about",
        hashid: "42",
        langid: "906008",
        control: [],
        submenu: [],
      }, //About
    ];

    return navigation;
  }
  if (sys_region_code == "cz_else") {
    var navigation = [
      //internet
      {
        tab: "internet",
        id: "ipv6-firewall-rules",
        hashid: "ipv6-firewall-rules",
        langid: "SUB_NAVIGATION_ITEM_IPV6_FIREWALL_RULES",
        control: ["sys_ipv6_status", "sys_ipv6_firewall_support"],
        submenu: [],
      }, //IPv6 Firewall Rules
      {
        tab: "internet",
        id: "port-mapping",
        hashid: "26",
        langid: "903005",
        control: [],
        submenu: [],
      }, //Port Mapping
      {
        tab: "internet",
        id: "exposed-host",
        hashid: "27",
        langid: "903006",
        control: [],
        submenu: [],
      }, //DMZ
      {
        tab: "internet",
        id: "parental-control",
        hashid: "23",
        langid: "PAGE_PAGE_PARENTAL_CONTROL_TITLE",
        control: [],
        submenu: [],
      }, //Parental Control
      {
        tab: "internet",
        id: "dns",
        hashid: "dns",
        langid: "SUB_NAVIGATION_ITEM_DNS",
        control: [],
        submenu: [],
      }, //DNS
      {
        tab: "internet",
        id: "ddns",
        hashid: "29",
        langid: "SUB_NAVIGATION_ITEM_DDNS",
        control: [],
        submenu: [],
      }, //DDNS
      {
        tab: "internet",
        id: "firewall",
        hashid: "22",
        langid: "903001",
        control: [],
        submenu: [],
      }, //Firewall
      {
        tab: "internet",
        id: "static_nat_host",
        hashid: "static_nat_host",
        langid: "SUB_NAVIGATION_ITEM_STATIC_NAT_HOST",
        control: ["sys_static_nat_support"],
        submenu: [],
      }, //Static NAT Host
      {
        tab: "internet",
        id: "vpn-settings",
        hashid: "vpn-settings",
        langid: "SUB_NAVIGATION_ITEM_VPN_SETTINGS",
        control: ["sys_vpn_settings_support"],
        submenu: [],
      }, //VPN Settings

      //wifi
      {
        tab: "wifi",
        id: "general",
        hashid: "35",
        langid: "904001",
        control: ["sys_router_mode"],
        submenu: [],
      }, //General
      {
        tab: "wifi",
        id: "schedule",
        hashid: "36",
        langid: "PAGE_SCHEDULE_TITLE",
        control: ["sys_router_mode"],
        submenu: [],
      }, //Power Saving Mode
      {
        tab: "wifi",
        id: "wps",
        hashid: "37",
        langid: "904003",
        control: ["sys_router_mode"],
        submenu: [],
      }, //WPS
      {
        tab: "wifi",
        id: "mac-filter",
        hashid: "38",
        langid: "904004",
        control: ["sys_router_mode"],
        submenu: [],
      }, //MAC Filter
      {
        tab: "wifi",
        id: "wifi-settings",
        hashid: "40",
        langid: "904006",
        control: ["sys_router_mode"],
        submenu: [],
      }, //Settings
      {
        tab: "wifi",
        id: "wifi-vf-wifi-network",
        hashid: "102",
        langid: "904008",
        control: [
          "sys_router_mode",
          "sys_fon_status",
          "show_wifi_vfwifinetwork",
        ],
        submenu: [],
      }, //VF WiFi network
      {
        tab: "wifi",
        id: "band_steering",
        hashid: "band_steering",
        langid: "PAGE_BAND_STEERING_TITLE",
        control: [
          "sys_router_mode",
          "sys_band_steering",
          "show_wifi_bandsteering",
        ],
        submenu: [],
      }, //Band Steering
      {
        tab: "wifi",
        id: "analyser-2-4",
        hashid: "analyser-2-4",
        langid: "PAGE_2_4_GHZ_ANALYSER_2-4_TITLE",
        control: ["sys_router_mode", "sys_is_super_wifi_mode_not_Active"],
        submenu: [],
      }, //2.4GHz
      {
        tab: "wifi",
        id: "analyser-5",
        hashid: "analyser-5",
        langid: "PAGE_5_GHZ_ANALYSER_5_TITLE",
        control: ["sys_router_mode", "sys_is_super_wifi_mode_not_Active"],
        submenu: [],
      }, //5GHz

      //settings
      {
        tab: "settings",
        id: "password",
        hashid: "60",
        langid: "905001",
        control: [],
        submenu: [],
      }, //Password
      {
        tab: "settings",
        id: "energy-settings",
        hashid: "55",
        langid: "PAGE_ENERGY_SETTINGS_TITLE",
        control: ["show_settings_energysettings"],
        submenu: [],
      }, //Energy Settings
      {
        tab: "settings",
        id: "usb",
        hashid: "58",
        langid: "905003",
        control: ["sys_usb_status"],
        submenu: [],
      }, //USB
      {
        tab: "settings",
        id: "content-sharing",
        hashid: "56",
        langid: "SUB_NAVIGATION_ITEM_CONTENT_SHARING",
        control: ["sys_usb_status"],
        submenu: [
          //Content Sharing
          {
            tab: "settings",
            id: "dlna",
            hashid: "57",
            langid: "905004",
            control: ["sys_usb_status"],
            submenu: [],
          }, //DLNA
          {
            tab: "settings",
            id: "network-share-samba",
            hashid: "51",
            langid: "SUB_SUB_NAVIGATION_ITEM_NETWORK_SHARE_SAMBA",
            control: ["sys_usb_status"],
            submenu: [],
          }, //Samba
          {
            tab: "settings",
            id: "ftp",
            hashid: "50",
            langid: "905011",
            control: ["sys_usb_status"],
            submenu: [],
          }, //FTP
          {
            tab: "settings",
            id: "upnp",
            hashid: "85",
            langid: "315001",
            control: ["sys_usb_status"],
            submenu: [],
          }, //UPnP
        ],
      },
      {
        tab: "settings",
        id: "printer-sharing",
        hashid: "83",
        langid: "521001",
        control: ["sys_usb_status", "show_settings_printersharing"],
        submenu: [],
      }, //Printer Sharing
      {
        tab: "settings",
        id: "configuration",
        hashid: "54",
        langid: "905007",
        control: [],
        submenu: [],
      }, //Configuration
      {
        tab: "settings",
        id: "lan",
        hashid: "52",
        langid: "905009",
        control: ["sys_router_mode"],
        submenu: [],
      }, //LAN
      {
        tab: "settings",
        id: "sfp-reg-id",
        hashid: "sfp-reg-id",
        langid: "SUB_NAVIGATION_ITEM_SFP_REG_ID",
        control: ["sys_sfp_status"],
        submenu: [],
      }, //SFP REG ID
      {
        tab: "settings",
        id: "openmodem",
        hashid: "openmodem",
        langid: "SUB_NAVIGATION_ITEM_GENERIC_MODEM",
        control: ["sys_openmodem_status"],
        submenu: [],
      }, //Open Modem
      //{tab:'settings', id:'openmodem_internet_time', hashid:'openmodem_internet_time', langid:'513001', control:["sys_openmodem_status","sys_openmodem_subpages_status"], submenu:[]}, //Internet Time
      {
        tab: "settings",
        id: "internet-time",
        hashid: "74",
        langid: "513001",
        control: [],
        submenu: [],
      }, //Internet Time
      {
        tab: "settings",
        id: "modem-mode",
        hashid: "modem-mode",
        langid: "PAGE_MODEM_MODE_TITLE",
        control: [],
        submenu: [],
      }, //modem-mode

      //status-and-support
      {
        tab: "status-and-support",
        id: "status",
        hashid: "1",
        langid: "906001",
        control: [],
        submenu: [
          //Status
          {
            tab: "status-and-support",
            id: "gpon_status",
            hashid: "gpon_status",
            langid: "1301761",
            control: [],
            submenu: [],
          }, //GPON Status
          {
            tab: "status-and-support",
            id: "vdsl_status",
            hashid: "66",
            langid: "1300081",
            control: ["show_ss_vdsl"],
            submenu: [],
          }, //VDSL Status
          {
            tab: "status-and-support",
            id: "fibre_status",
            hashid: "82",
            langid: "907003",
            control: ["show_ss_fibre"],
            submenu: [],
          }, //Fibre Statuss
          {
            tab: "status-and-support",
            id: "wan_status",
            hashid: "67",
            langid: "906013",
            control: [],
            submenu: [],
          }, //WAN Status
          {
            tab: "status-and-support",
            id: "optical_status",
            hashid: "201",
            langid: "1301726",
            control: [],
            submenu: [],
          }, //Optical Status
          {
            tab: "status-and-support",
            id: "lan_status",
            hashid: "70",
            langid: "906014",
            control: [],
            submenu: [],
          }, //LAN Status
          {
            tab: "status-and-support",
            id: "routing_status",
            hashid: "71",
            langid: "906015",
            control: [],
            submenu: [],
          }, //Routing
          {
            tab: "status-and-support",
            id: "umts_status",
            hashid: "44",
            langid: "1301451",
            control: ["sys_umts_status", "show_ss_mobile"],
            submenu: [],
          }, //Mobile Status
        ],
      },
      {
        tab: "status-and-support",
        id: "diagnostic-utility",
        hashid: "4",
        langid: "906004",
        control: [],
        submenu: [],
      }, //Diagnostic Utility
      {
        tab: "status-and-support",
        id: "restart",
        hashid: "41",
        langid: "906007",
        control: [],
        submenu: [],
      }, //Restart
      {
        tab: "status-and-support",
        id: "event-log",
        hashid: "6",
        langid: "906006",
        control: [],
        submenu: [],
      }, //Event Log
      {
        tab: "status-and-support",
        id: "about",
        hashid: "42",
        langid: "906008",
        control: [],
        submenu: [],
      }, //About
    ];

    return navigation;
  } else {
    var navigation = [
      {
        tab: "phone",
        id: "phone-settings",
        hashid: "20",
        langid: "SUB_SUB_NAVIGATION_ITEM_PHONE_SETTINGS",
        control: [],
        submenu: [],
      }, //Phone Settings
      {
        tab: "phone",
        id: "call-log",
        hashid: "7",
        langid: "902001",
        control: [],
        submenu: [],
      }, //Call Log
      //{tab:'phone', id:'ringing-schedule', hashid:'16', langid:'902010', control:['show_phone_ringschedule'], submenu:[]}, //Ringing Schedule
      {
        tab: "phone",
        id: "phone-numbers",
        hashid: "17",
        langid: "902011",
        control: [],
        submenu: [],
      }, //Phone Numbers
      {
        tab: "phone",
        id: "number-blocking",
        hashid: "number-blocking",
        langid: "209001",
        control: ["sys_number_block"],
        submenu: [],
      }, //number blocking
      //{tab:'phone', id:'call-settings', hashid:'79', langid:'902019', control:[], submenu:[]}, //Call Settings
      //internet
      {
        tab: "internet",
        id: "umts",
        hashid: "89",
        langid: "SUB_NAVIGATION_ITEM_MOBILE",
        control: ["sys_umts_status", "show_internet_mobile"],
        submenu: [],
      }, //UMTS
      {
        tab: "internet",
        id: "ipv6-firewall-rules",
        hashid: "ipv6-firewall-rules",
        langid: "SUB_NAVIGATION_ITEM_IPV6_FIREWALL_RULES",
        control: ["sys_ipv6_status", "sys_ipv6_firewall_support"],
        submenu: [],
      }, //IPv6 Firewall Rules
      {
        tab: "internet",
        id: "port-mapping",
        hashid: "26",
        langid: "903005",
        control: [],
        submenu: [],
      }, //Port Mapping
      {
        tab: "internet",
        id: "exposed-host",
        hashid: "27",
        langid: "903006",
        control: [],
        submenu: [],
      }, //DMZ
      {
        tab: "internet",
        id: "parental-control",
        hashid: "23",
        langid: "PAGE_PAGE_PARENTAL_CONTROL_TITLE",
        control: [],
        submenu: [],
      }, //Parental Control
      {
        tab: "internet",
        id: "dns",
        hashid: "dns",
        langid: "SUB_NAVIGATION_ITEM_DNS",
        control: [],
        submenu: [],
      }, //DNS
      {
        tab: "internet",
        id: "ddns",
        hashid: "29",
        langid: "SUB_NAVIGATION_ITEM_DDNS",
        control: [],
        submenu: [],
      }, //DDNS

      {
        tab: "internet",
        id: "firewall",
        hashid: "22",
        langid: "903001",
        control: [],
        submenu: [],
      }, //Firewall
      //{tab:'internet', id:'wolan', hashid:'wolan', langid:'PAGE_WOLAN_TITLE', control:['show_internet_wolan'], submenu:[]}, //WoLAN
      {
        tab: "internet",
        id: "static_nat_host",
        hashid: "static_nat_host",
        langid: "SUB_NAVIGATION_ITEM_STATIC_NAT_HOST",
        control: ["sys_static_nat_support"],
        submenu: [],
      }, //Static NAT Host
      {
        tab: "internet",
        id: "vpn-settings",
        hashid: "vpn-settings",
        langid: "SUB_NAVIGATION_ITEM_VPN_SETTINGS",
        control: ["sys_vpn_settings_support"],
        submenu: [],
      }, //VPN Settings
      //wifi
      {
        tab: "wifi",
        id: "general",
        hashid: "35",
        langid: "904001",
        control: [],
        submenu: [],
      }, //General
      {
        tab: "wifi",
        id: "schedule",
        hashid: "36",
        langid: "PAGE_SCHEDULE_TITLE",
        control: [],
        submenu: [],
      }, //Power Saving Mode
      {
        tab: "wifi",
        id: "wps",
        hashid: "37",
        langid: "904003",
        control: [],
        submenu: [
          //WPS
          {
            tab: "wifi",
            id: "pairing-smart-app",
            hashid: "pairing-smart-app",
            langid: "SUB_NAVIGATION_ITEM_WPS_PAIRING",
            control: ["sys_smartapp_status"],
            submenu: [],
          }, //Pairing Smart App
        ],
      },
      {
        tab: "wifi",
        id: "mac-filter",
        hashid: "38",
        langid: "904004",
        control: [],
        submenu: [],
      }, //MAC Filter
      {
        tab: "wifi",
        id: "wifi-settings",
        hashid: "40",
        langid: "904006",
        control: [],
        submenu: [],
      }, //Settings
      {
        tab: "wifi",
        id: "band_steering",
        hashid: "band_steering",
        langid: "PAGE_BAND_STEERING_TITLE",
        control: ["sys_band_steering", "show_wifi_bandsteering"],
        submenu: [],
      }, //Band Steering
      {
        tab: "wifi",
        id: "analyser-2-4",
        hashid: "analyser-2-4",
        langid: "SUB_NAVIGATION_ITEM_ANALYSER_2-4",
        control: ["sys_is_super_wifi_mode_not_Active"],
        submenu: [],
      }, //2.4GHz
      {
        tab: "wifi",
        id: "analyser-5",
        hashid: "analyser-5",
        langid: "SUB_NAVIGATION_ITEM_ANALYSER_5",
        control: ["sys_is_super_wifi_mode_not_Active"],
        submenu: [],
      }, //5GHz
      //{tab:'wifi', id:'super_wifi', hashid:'super_wifi', langid:'SUB_NAVIGATION_ITEM_SUPER_WIFI', control:['support_super_wifi'], submenu:[]}, //SuperWiFi
      /*
        //messages
		{tab:'messages', id:'content-create_message', hashid:'create_message', langid:'SUB_NAVIGATION_ITEM_CREATE_MESSAGE', control:[], submenu:[]}, //Create Message
		{tab:'messages', id:'content-inbox', hashid:'inbox', langid:'SUB_NAVIGATION_ITEM_INBOX', control:[], submenu:[]}, //Inbox
		{tab:'messages', id:'content-sent', hashid:'sent', langid:'SUB_NAVIGATION_ITEM_SENT', control:[], submenu:[]}, //Sent
		{tab:'messages', id:'content-outbox', hashid:'outbox', langid:'SUB_NAVIGATION_ITEM_OUTBOX', control:[], submenu:[]}, //Outbox
		*/
      //settings

      {
        tab: "settings",
        id: "password",
        hashid: "60",
        langid: "905001",
        control: [],
        submenu: [],
      }, //Password
      {
        tab: "settings",
        id: "vodafone_safe_netwok",
        hashid: "vodafone_safe_netwok",
        langid: "SUB_NAVIGATION_ITEM_VODAFONE_SAFE_NETWORK",
        control: ["sys_vodafone_safe_netwok"],
        submenu: [],
      }, //Safe Network
      {
        tab: "settings",
        id: "energy-settings",
        hashid: "55",
        langid: "PAGE_ENERGY_SETTINGS_TITLE",
        control: ["show_settings_energysettings"],
        submenu: [],
      }, //Energy Settings
      {
        tab: "settings",
        id: "usb",
        hashid: "58",
        langid: "905003",
        control: ["sys_usb_status"],
        submenu: [],
      }, //USB
      {
        tab: "settings",
        id: "content-sharing",
        hashid: "56",
        langid: "SUB_NAVIGATION_ITEM_CONTENT_SHARING",
        control: ["sys_usb_status"],
        submenu: [
          //Content Sharing
          {
            tab: "settings",
            id: "dlna",
            hashid: "57",
            langid: "905004",
            control: ["sys_usb_status"],
            submenu: [],
          }, //DLNA
          {
            tab: "settings",
            id: "network-share-samba",
            hashid: "51",
            langid: "SUB_SUB_NAVIGATION_ITEM_NETWORK_SHARE_SAMBA",
            control: ["sys_usb_status"],
            submenu: [],
          }, //Samba
          {
            tab: "settings",
            id: "ftp",
            hashid: "50",
            langid: "905011",
            control: ["sys_usb_status"],
            submenu: [],
          }, //FTP
          {
            tab: "settings",
            id: "upnp",
            hashid: "85",
            langid: "315001",
            control: ["sys_usb_status"],
            submenu: [],
          }, //UPnP
        ],
      },
      {
        tab: "settings",
        id: "printer-sharing",
        hashid: "83",
        langid: "521001",
        control: ["sys_usb_status", "show_settings_printersharing"],
        submenu: [],
      }, //Printer Sharing
      {
        tab: "settings",
        id: "configuration",
        hashid: "54",
        langid: "905007",
        control: [],
        submenu: [],
      }, //Configuration
      {
        tab: "settings",
        id: "lan",
        hashid: "52",
        langid: "905009",
        control: [],
        submenu: [],
      }, //LAN
      //{tab:'settings', id:'umts-settings', hashid:'88', langid:'1301442', control:['sys_umts_status', 'show_settings_mobile'], submenu:[]}, //Mobile
      {
        tab: "settings",
        id: "sfp-reg-id",
        hashid: "sfp-reg-id",
        langid: "SUB_NAVIGATION_ITEM_SFP_REG_ID",
        control: ["sys_sfp_status"],
        submenu: [],
      }, //SFP REG ID
      {
        tab: "settings",
        id: "openmodem",
        hashid: "openmodem",
        langid: "SUB_NAVIGATION_ITEM_GENERIC_MODEM",
        control: ["sys_openmodem_status"],
        submenu: [
          //Open Modem
          //{tab:'settings', id:'openmodem_wan', hashid:'openmodem_wan', langid:'903013', control:["sys_openmodem_status"], submenu:[]}, //WAN
          {
            tab: "settings",
            id: "openmodem_internet_time",
            hashid: "openmodem_internet_time",
            langid: "513001",
            control: ["sys_openmodem_status", "sys_openmodem_subpages_status"],
            submenu: [],
          }, //Internet Time
          {
            tab: "settings",
            id: "openmodem_phone_settings",
            hashid: "openmodem_phone_settings",
            langid: "SUB_SUB_NAVIGATION_ITEM_PHONE_SETTINGS",
            control: ["sys_openmodem_status", "sys_openmodem_subpages_status"],
            submenu: [],
          }, //Phone Settings
        ],
      },
      //status-and-support
      {
        tab: "status-and-support",
        id: "status",
        hashid: "1",
        langid: "906001",
        control: [],
        submenu: [
          //Status
          {
            tab: "status-and-support",
            id: "voice_status",
            hashid: "3",
            langid: "906003",
            control: [],
            submenu: [],
          }, //Voice Status
          {
            tab: "status-and-support",
            id: "gpon_status",
            hashid: "gpon_status",
            langid: "1301761",
            control: [],
            submenu: [],
          }, //GPON Status
          {
            tab: "status-and-support",
            id: "dongle-connectivity",
            hashid: "dongle-connectivity",
            langid: "SUB_SUB_NAVIGATION_ITEM_DONGLE_CONNECTIVITY",
            control: ["sys_umts_status"],
            submenu: [],
          }, //Dongle Connectivity
        ],
      },
      {
        tab: "status-and-support",
        id: "diagnostic-utility",
        hashid: "4",
        langid: "906004",
        control: [],
        submenu: [],
      }, //Diagnostic Utility
      {
        tab: "status-and-support",
        id: "restart",
        hashid: "41",
        langid: "906007",
        control: [],
        submenu: [],
      }, //Restart
      {
        tab: "status-and-support",
        id: "event-log",
        hashid: "6",
        langid: "906006",
        control: [],
        submenu: [],
      }, //Event Log
      {
        tab: "status-and-support",
        id: "about",
        hashid: "42",
        langid: "906008",
        control: [],
        submenu: [],
      }, //About
    ];

    return navigation;
  }
}

function _obj_navigation_admin() {
  if (sys_region_code == "sp_else") {
    var navigation = [
      //phone
      {
        tab: "phone",
        id: "call-settings",
        hashid: "79",
        langid: "SUB_SUB_NAVIGATION_ITEM_PHONE_SETTINGS",
        control: [],
        submenu: [],
      }, //Call Settings
      {
        tab: "phone",
        id: "phone-numbers",
        hashid: "17",
        langid: "902011",
        control: [],
        submenu: [
          //Phone Numbers
          {
            tab: "phone",
            id: "phone-settingsadv",
            hashid: "phone-settingsadv",
            langid: "SUB_NAVIGATION_ITEM_PHONE_SETTINGS",
            control: [],
            submenu: [],
          }, //Phone Settings
        ],
      },
      {
        tab: "phone",
        id: "call-log",
        hashid: "7",
        langid: "902001",
        control: [],
        submenu: [],
      }, //Call Log
      {
        tab: "phone",
        id: "ringing-schedule",
        hashid: "16",
        langid: "902010",
        control: ["show_phone_ringschedule"],
        submenu: [],
      }, //Ringing Schedule
      //{tab:'phone', id:'number-blocking', hashid:'number-blocking', langid:'209001', control:['sys_number_block'], submenu:[]}, //number blocking
      //internet
      {
        tab: "internet",
        id: "firewall",
        hashid: "22",
        langid: "903001",
        control: [],
        submenu: [
          //Firewall
          {
            tab: "internet",
            id: "content-dos",
            hashid: "content-dos",
            langid: "1310012",
            control: [],
            submenu: [],
          }, //, //DoS
          //{tab:'internet', id:'content-access-control-list', hashid:'content-access-control-list', langid:'PAGE_ACCESS_CONTROL_LIST_TITLE', control:[], submenu:[]} //Access Control List
        ],
      },
      //{tab:'internet', id:'ipv6-firewall-rules', hashid:'ipv6-firewall-rules', langid:'SUB_NAVIGATION_ITEM_IPV6_FIREWALL_RULES', control:['sys_ipv6_status', 'sys_ipv6_firewall_support'], submenu:[]}, //IPv6 Firewall Rules
      {
        tab: "internet",
        id: "umts",
        hashid: "89",
        langid: "SUB_NAVIGATION_ITEM_MOBILE",
        control: ["sys_umts_status", "show_internet_mobile"],
        submenu: [],
      }, //UMTS
      {
        tab: "internet",
        id: "port-mapping",
        hashid: "26",
        langid: "903005",
        control: [],
        submenu: [],
      }, //Port Mapping
      {
        tab: "internet",
        id: "exposed-host",
        hashid: "27",
        langid: "903006",
        control: [],
        submenu: [],
      }, //DMZ
      {
        tab: "internet",
        id: "parental-control",
        hashid: "23",
        langid: "PAGE_PAGE_PARENTAL_CONTROL_TITLE",
        control: [],
        submenu: [],
      }, //Parental Control
      {
        tab: "internet",
        id: "dns",
        hashid: "dns",
        langid: "SUB_NAVIGATION_ITEM_DNS",
        control: [],
        submenu: [],
      }, //DNS
      {
        tab: "internet",
        id: "ddns",
        hashid: "29",
        langid: "SUB_NAVIGATION_ITEM_DDNS",
        control: [],
        submenu: [],
      }, //DDNS

      //{tab:'internet', id:'static_nat_host', hashid:'static_nat_host', langid:'SUB_NAVIGATION_ITEM_STATIC_NAT_HOST', control:['sys_static_nat_support'], submenu:[]}, //Static NAT Host
      //{tab:'internet', id:'vpn-settings', hashid:'vpn-settings', langid:'SUB_NAVIGATION_ITEM_VPN_SETTINGS', control:['sys_vpn_settings_support'], submenu:[]}, //VPN Settings
      {
        tab: "internet",
        id: "wolan",
        hashid: "wolan",
        langid: "PAGE_WOLAN_TITLE",
        control: ["show_internet_wolan"],
        submenu: [],
      }, //WoLAN
      //wifi
      {
        tab: "wifi",
        id: "general",
        hashid: "35",
        langid: "904001",
        control: [],
        submenu: [],
      }, //General
      {
        tab: "wifi",
        id: "schedule",
        hashid: "36",
        langid: "PAGE_SCHEDULE_TITLE",
        control: [],
        submenu: [],
      }, //Power Saving Mode
      {
        tab: "wifi",
        id: "wps",
        hashid: "37",
        langid: "904003",
        control: [],
        submenu: [
          //WPS
          //{tab:'wifi', id:'pairing-smart-app', hashid:'pairing-smart-app', langid:'SUB_NAVIGATION_ITEM_WPS_PAIRING', control:["sys_smartapp_status"], submenu:[]} //Pairing Smart App
        ],
      },
      {
        tab: "wifi",
        id: "mac-filter",
        hashid: "38",
        langid: "904004",
        control: [],
        submenu: [],
      }, //MAC Filter
      {
        tab: "wifi",
        id: "wifi-settings",
        hashid: "40",
        langid: "904006",
        control: [],
        submenu: [],
      }, //Settings
      //{tab:'wifi', id:'wifi-vf-wifi-network', hashid:'102', langid:'904008', control:['sys_fon_status', 'show_wifi_vfwifinetwork'], submenu:[]}, //VF WiFi network
      {
        tab: "wifi",
        id: "analyser-2-4",
        hashid: "analyser-2-4",
        langid: "PAGE_2_4_GHZ_ANALYSER_2-4_TITLE",
        control: [],
        submenu: [],
      }, //2.4GHz
      {
        tab: "wifi",
        id: "analyser-5",
        hashid: "analyser-5",
        langid: "PAGE_5_GHZ_ANALYSER_5_TITLE",
        control: [],
        submenu: [],
      }, //5GHz
      {
        tab: "wifi",
        id: "client-monitoring",
        hashid: "client-monitoring",
        langid: "1310006",
        control: ["show_wifi_clientmonitor"],
        submenu: [],
      }, //Client Monitoring
      {
        tab: "wifi",
        id: "band_steering",
        hashid: "band_steering",
        langid: "PAGE_BAND_STEERING_TITLE",
        control: ["sys_band_steering", "show_wifi_bandsteering"],
        submenu: [],
      }, //Band Steering
      {
        tab: "wifi",
        id: "super_wifi",
        hashid: "super_wifi",
        langid: "SUB_NAVIGATION_ITEM_SUPER_WIFI",
        control: ["support_super_wifi"],
        submenu: [],
      }, //SuperWiFi
      /*
        //messages
		{tab:'messages', id:'content-create_message', hashid:'create_message', langid:'SUB_NAVIGATION_ITEM_CREATE_MESSAGE', control:[], submenu:[]}, //Create Message
		{tab:'messages', id:'content-inbox', hashid:'inbox', langid:'SUB_NAVIGATION_ITEM_INBOX', control:[], submenu:[]}, //Inbox
		{tab:'messages', id:'content-sent', hashid:'sent', langid:'SUB_NAVIGATION_ITEM_SENT', control:[], submenu:[]}, //Sent
		{tab:'messages', id:'content-outbox', hashid:'outbox', langid:'SUB_NAVIGATION_ITEM_OUTBOX', control:[], submenu:[]}, //Outbox
		*/
      //settings
      {
        tab: "settings",
        id: "password",
        hashid: "60",
        langid: "905001",
        control: [],
        submenu: [],
      }, //Password
      //{tab:'settings', id:'vodafone_safe_netwok', hashid:'vodafone_safe_netwok', langid:'SUB_NAVIGATION_ITEM_VODAFONE_SAFE_NETWORK', control:['sys_vodafone_safe_netwok'], submenu:[]}, //Safe Network
      {
        tab: "settings",
        id: "energy-settings",
        hashid: "55",
        langid: "PAGE_ENERGY_SETTINGS_TITLE",
        control: ["show_settings_energysettings"],
        submenu: [],
      }, //Energy Settings
      {
        tab: "settings",
        id: "usb",
        hashid: "58",
        langid: "905003",
        control: ["sys_usb_status"],
        submenu: [],
      }, //USB
      {
        tab: "settings",
        id: "content-sharing",
        hashid: "56",
        langid: "SUB_NAVIGATION_ITEM_CONTENT_SHARING",
        control: ["sys_usb_status"],
        submenu: [
          //Content Sharing
          {
            tab: "settings",
            id: "dlna",
            hashid: "57",
            langid: "905004",
            control: ["sys_usb_status"],
            submenu: [],
          }, //DLNA
          {
            tab: "settings",
            id: "network-share-samba",
            hashid: "51",
            langid: "SUB_SUB_NAVIGATION_ITEM_NETWORK_SHARE_SAMBA",
            control: ["sys_usb_status"],
            submenu: [],
          }, //Samba
          {
            tab: "settings",
            id: "ftp",
            hashid: "50",
            langid: "905011",
            control: ["sys_usb_status"],
            submenu: [],
          }, //FTP
          {
            tab: "settings",
            id: "upnp",
            hashid: "85",
            langid: "315001",
            control: ["sys_usb_status"],
            submenu: [],
          }, //UPnP
        ],
      },
      {
        tab: "settings",
        id: "printer-sharing",
        hashid: "83",
        langid: "521001",
        control: ["sys_usb_status", "show_settings_printersharing"],
        submenu: [],
      }, //Printer Sharing
      {
        tab: "settings",
        id: "configuration",
        hashid: "54",
        langid: "905007",
        control: [],
        submenu: [],
      }, //Configuration
      {
        tab: "settings",
        id: "lan",
        hashid: "52",
        langid: "905009",
        control: [],
        submenu: [],
      }, //LAN
      {
        tab: "settings",
        id: "firmware-update",
        hashid: "59",
        langid: "905002",
        control: ["sys_debug_fw"],
        submenu: [],
      }, //Firmware Update
      {
        tab: "settings",
        id: "qos",
        hashid: "73",
        langid: "905018",
        control: [],
        submenu: [
          //QoS
          // {tab:'settings', id:'rate_limit', hashid:'rate_limit', langid:'1301901', control:[], submenu:[]} //Rate Limit
        ],
      },
      {
        tab: "settings",
        id: "internet-time",
        hashid: "74",
        langid: "513001",
        control: [],
        submenu: [],
      }, //Internet Time
      {
        tab: "settings",
        id: "tr-069",
        hashid: "75",
        langid: "905019",
        control: [],
        submenu: [],
      }, //TR-069
      {
        tab: "settings",
        id: "snmp",
        hashid: "76",
        langid: "905020",
        control: ["show_settings_snmp"],
        submenu: [],
      }, //SNMP
      {
        tab: "settings",
        id: "settings-access-control",
        hashid: "80",
        langid: "906017",
        control: [],
        submenu: [],
      }, //Access control
      {
        tab: "settings",
        id: "xdsl",
        hashid: "90",
        langid: "903017",
        control: ["show_settings_xdsl"],
        submenu: [],
      }, //xDSL
      {
        tab: "settings",
        id: "wan",
        hashid: "92",
        langid: "903013",
        control: [],
        submenu: [],
      }, //WAN
      {
        tab: "settings",
        id: "ipv6-basic-configuration",
        hashid: "97",
        langid: "905023",
        control: ["sys_ipv6_status"],
        submenu: [],
      }, //IPv6 Basic Configuration
      {
        tab: "settings",
        id: "static-routing",
        hashid: "86",
        langid: "522001",
        control: [],
        submenu: [],
      }, //Static Routing
      {
        tab: "settings",
        id: "policy-routing",
        hashid: "93",
        langid: "903018",
        control: [],
        submenu: [],
      }, //Policy Routing
      {
        tab: "settings",
        id: "gpon",
        hashid: "109",
        langid: "1301500",
        control: [],
        submenu: [],
      }, //GPON
      {
        tab: "settings",
        id: "lan_switch",
        hashid: "lan_switch",
        langid: "1301701",
        control: [],
        submenu: [],
      }, //lan switch
      {
        tab: "settings",
        id: "iptv",
        hashid: "108",
        langid: "903019",
        control: ["sys_iptv_status"],
        submenu: [],
      }, //TV Settings
      {
        tab: "settings",
        id: "igmp_proxy",
        hashid: "igmp_proxy",
        langid: "1301462",
        control: [],
        submenu: [],
      }, //igmp proxy
      {
        tab: "settings",
        id: "umts-settings",
        hashid: "88",
        langid: "1301442",
        control: ["sys_umts_status", "show_settings_mobile"],
        submenu: [],
      }, //Mobile
      //{tab:'settings', id:'sfp-reg-id', hashid:'sfp-reg-id', langid:'SUB_NAVIGATION_ITEM_SFP_REG_ID', control:['sys_sfp_status'], submenu:[]}, //SFP REG ID
      /*{tab:'settings', id:'openmodem', hashid:'openmodem', langid:'SUB_NAVIGATION_ITEM_GENERIC_MODEM', control:["sys_openmodem_status"], submenu:[ //Open Modem
			//{tab:'settings', id:'openmodem_wan', hashid:'openmodem_wan', langid:'903013', control:["sys_openmodem_status"], submenu:[]}, //WAN
			{tab:'settings', id:'openmodem_internet_time', hashid:'openmodem_internet_time', langid:'513001', control:["sys_openmodem_status","sys_openmodem_subpages_status"], submenu:[]}, //Internet Time
			{tab:'settings', id:'openmodem_phone_settings', hashid:'openmodem_phone_settings', langid:'SUB_SUB_NAVIGATION_ITEM_PHONE_SETTINGS', control:["sys_openmodem_status","sys_openmodem_subpages_status"], submenu:[]} //Phone Settings
		]},*/
      //status-and-support
      {
        tab: "status-and-support",
        id: "status",
        hashid: "1",
        langid: "906001",
        control: [],
        submenu: [
          //Status
          {
            tab: "status-and-support",
            id: "voice_status",
            hashid: "3",
            langid: "906003",
            control: [],
            submenu: [],
          }, //Voice Status
          {
            tab: "status-and-support",
            id: "vdsl_status",
            hashid: "66",
            langid: "1300081",
            control: ["show_ss_vdsl"],
            submenu: [],
          }, //VDSL Status
          {
            tab: "status-and-support",
            id: "fibre_status",
            hashid: "82",
            langid: "907003",
            control: ["show_ss_fibre"],
            submenu: [],
          }, //Fibre Statuss
          {
            tab: "status-and-support",
            id: "wan_status",
            hashid: "67",
            langid: "906013",
            control: [],
            submenu: [],
          }, //WAN Status
          {
            tab: "status-and-support",
            id: "optical_status",
            hashid: "201",
            langid: "1301726",
            control: [],
            submenu: [],
          }, //Optical Status
          {
            tab: "status-and-support",
            id: "lan_status",
            hashid: "70",
            langid: "906014",
            control: [],
            submenu: [],
          }, //LAN Status
          {
            tab: "status-and-support",
            id: "gpon_status",
            hashid: "gpon_status",
            langid: "1301761",
            control: [],
            submenu: [],
          }, //GPON Status
          //{tab:'status-and-support', id:'dongle-connectivity', hashid:'dongle-connectivity', langid:'SUB_SUB_NAVIGATION_ITEM_DONGLE_CONNECTIVITY', control:['sys_umts_status'], submenu:[]}, //Dongle Connectivity
          {
            tab: "status-and-support",
            id: "iptv_status",
            hashid: "202",
            langid: "1301749",
            control: [],
            submenu: [],
          }, //iptv status
          {
            tab: "status-and-support",
            id: "routing_status",
            hashid: "71",
            langid: "906015",
            control: [],
            submenu: [],
          }, //Routing
          {
            tab: "status-and-support",
            id: "umts_status",
            hashid: "44",
            langid: "1301451",
            control: ["sys_umts_status", "show_ss_mobile"],
            submenu: [],
          }, //Mobile Status
        ],
      },
      {
        tab: "status-and-support",
        id: "diagnostic-utility",
        hashid: "4",
        langid: "906004",
        control: [],
        submenu: [
          //Diagnostic Utility
          {
            tab: "status-and-support",
            id: "gpon-debug",
            hashid: "110",
            langid: "1301511",
            control: [],
            submenu: [],
          }, //GPON Debug
          // {tab:'status-and-support', id:'trabsceuver_debug', hashid:'203', langid:'1301557', control:[], submenu:[]}, //Transceiver Debug
          {
            tab: "status-and-support",
            id: "voip-diagnostics",
            hashid: "87",
            langid: "616001",
            control: [],
            submenu: [],
          }, //VOIP Diagnostics
          // {tab:'status-and-support', id:'packet_trace', hashid:'204', langid:'1301943', control:[], submenu:[]}, //Packet Trace
          //{tab:'status-and-support', id:'trace_route', hashid:'205', langid:'1301958', control:[], submenu:[]}, //Trace Route
          {
            tab: "status-and-support",
            id: "debug_log",
            hashid: "debug_log",
            langid: "1101008",
            control: [],
            submenu: [],
          }, //Debug Log
          {
            tab: "status-and-support",
            id: "port-mirroring",
            hashid: "98",
            langid: "906019",
            control: [],
            submenu: [],
          }, //Port Mirroring
        ],
      },
      {
        tab: "status-and-support",
        id: "event-log",
        hashid: "6",
        langid: "906006",
        control: [],
        submenu: [],
      }, //Event Log
      {
        tab: "status-and-support",
        id: "restart",
        hashid: "41",
        langid: "906007",
        control: [],
        submenu: [],
      }, //Restart
      {
        tab: "status-and-support",
        id: "nat-mapping-table",
        hashid: "28",
        langid: "903007",
        control: [],
        submenu: [],
      }, //NAT Mapping Table
      {
        tab: "status-and-support",
        id: "about",
        hashid: "42",
        langid: "906008",
        control: [],
        submenu: [],
      }, //About
    ];
  } else {
    var navigation = [
      //phone
      {
        tab: "phone",
        id: "phone-settings",
        hashid: "20",
        langid: "SUB_SUB_NAVIGATION_ITEM_PHONE_SETTINGS",
        control: [],
        submenu: [],
      }, //Phone Settings
      {
        tab: "phone",
        id: "call-log",
        hashid: "7",
        langid: "902001",
        control: [],
        submenu: [],
      }, //Call Log
      //{tab:'phone', id:'ringing-schedule', hashid:'16', langid:'902010', control:['show_phone_ringschedule'], submenu:[]}, //Ringing Schedule
      {
        tab: "phone",
        id: "phone-numbers",
        hashid: "17",
        langid: "902011",
        control: [],
        submenu: [
          //Phone Numbers
        ],
      },
      {
        tab: "phone",
        id: "number-blocking",
        hashid: "number-blocking",
        langid: "209001",
        control: ["sys_number_block"],
        submenu: [],
      }, //number blocking
      //{tab:'phone', id:'call-settings', hashid:'79', langid:'902019', control:[], submenu:[]}, //Call Settings
      //internet
      {
        tab: "internet",
        id: "firewall",
        hashid: "22",
        langid: "903001",
        control: [],
        submenu: [
          //Firewall
          //{tab:'internet', id:'content-dos', hashid:'content-dos', langid:'1310012', control:[], submenu:[]}//, //DoS
          //{tab:'internet', id:'content-access-control-list', hashid:'content-access-control-list', langid:'PAGE_ACCESS_CONTROL_LIST_TITLE', control:[], submenu:[]} //Access Control List
        ],
      },
      {
        tab: "internet",
        id: "ipv6-firewall-rules",
        hashid: "ipv6-firewall-rules",
        langid: "SUB_NAVIGATION_ITEM_IPV6_FIREWALL_RULES",
        control: ["sys_ipv6_status", "sys_ipv6_firewall_support"],
        submenu: [],
      }, //IPv6 Firewall Rules
      {
        tab: "internet",
        id: "umts",
        hashid: "89",
        langid: "SUB_NAVIGATION_ITEM_MOBILE",
        control: ["sys_umts_status", "show_internet_mobile"],
        submenu: [],
      }, //UMTS
      {
        tab: "internet",
        id: "port-mapping",
        hashid: "26",
        langid: "903005",
        control: [],
        submenu: [],
      }, //Port Mapping
      {
        tab: "internet",
        id: "exposed-host",
        hashid: "27",
        langid: "903006",
        control: [],
        submenu: [],
      }, //DMZ
      {
        tab: "internet",
        id: "parental-control",
        hashid: "23",
        langid: "PAGE_PAGE_PARENTAL_CONTROL_TITLE",
        control: [],
        submenu: [],
      }, //Parental Control
      {
        tab: "internet",
        id: "dns",
        hashid: "dns",
        langid: "SUB_NAVIGATION_ITEM_DNS",
        control: [],
        submenu: [],
      }, //DNS
      {
        tab: "internet",
        id: "ddns",
        hashid: "29",
        langid: "SUB_NAVIGATION_ITEM_DDNS",
        control: [],
        submenu: [],
      }, //DDNS

      {
        tab: "internet",
        id: "static_nat_host",
        hashid: "static_nat_host",
        langid: "SUB_NAVIGATION_ITEM_STATIC_NAT_HOST",
        control: ["sys_static_nat_support"],
        submenu: [],
      }, //Static NAT Host
      {
        tab: "internet",
        id: "vpn-settings",
        hashid: "vpn-settings",
        langid: "SUB_NAVIGATION_ITEM_VPN_SETTINGS",
        control: ["sys_vpn_settings_support"],
        submenu: [],
      }, //VPN Settings
      {
        tab: "internet",
        id: "wolan",
        hashid: "wolan",
        langid: "PAGE_WOLAN_TITLE",
        control: ["show_internet_wolan"],
        submenu: [],
      }, //WoLAN
      //wifi
      {
        tab: "wifi",
        id: "general",
        hashid: "35",
        langid: "904001",
        control: [],
        submenu: [],
      }, //General
      {
        tab: "wifi",
        id: "schedule",
        hashid: "36",
        langid: "PAGE_SCHEDULE_TITLE",
        control: [],
        submenu: [],
      }, //Power Saving Mode
      {
        tab: "wifi",
        id: "wps",
        hashid: "37",
        langid: "904003",
        control: [],
        submenu: [
          //WPS
          {
            tab: "wifi",
            id: "pairing-smart-app",
            hashid: "pairing-smart-app",
            langid: "SUB_NAVIGATION_ITEM_WPS_PAIRING",
            control: ["sys_smartapp_status"],
            submenu: [],
          }, //Pairing Smart App
        ],
      },
      {
        tab: "wifi",
        id: "mac-filter",
        hashid: "38",
        langid: "904004",
        control: [],
        submenu: [],
      }, //MAC Filter
      {
        tab: "wifi",
        id: "wifi-settings",
        hashid: "40",
        langid: "904006",
        control: [],
        submenu: [],
      }, //Settings
      {
        tab: "wifi",
        id: "wifi-vf-wifi-network",
        hashid: "102",
        langid: "904008",
        control: ["sys_fon_status", "show_wifi_vfwifinetwork"],
        submenu: [],
      }, //VF WiFi network
      {
        tab: "wifi",
        id: "analyser-2-4",
        hashid: "analyser-2-4",
        langid: "PAGE_2_4_GHZ_ANALYSER_2-4_TITLE",
        control: ["sys_is_super_wifi_mode_not_Active"],
        submenu: [],
      }, //2.4GHz
      {
        tab: "wifi",
        id: "analyser-5",
        hashid: "analyser-5",
        langid: "PAGE_5_GHZ_ANALYSER_5_TITLE",
        control: ["sys_is_super_wifi_mode_not_Active"],
        submenu: [],
      }, //5GHz
      {
        tab: "wifi",
        id: "client-monitoring",
        hashid: "client-monitoring",
        langid: "1310006",
        control: ["show_wifi_clientmonitor"],
        submenu: [],
      }, //Client Monitoring
      {
        tab: "wifi",
        id: "band_steering",
        hashid: "band_steering",
        langid: "PAGE_BAND_STEERING_TITLE",
        control: ["sys_band_steering", "show_wifi_bandsteering"],
        submenu: [],
      }, //Band Steering
      //{tab:'wifi', id:'super_wifi', hashid:'super_wifi', langid:'SUB_NAVIGATION_ITEM_SUPER_WIFI', control:['support_super_wifi'], submenu:[]}, //SuperWiFi
      /*
        //messages
		{tab:'messages', id:'content-create_message', hashid:'create_message', langid:'SUB_NAVIGATION_ITEM_CREATE_MESSAGE', control:[], submenu:[]}, //Create Message
		{tab:'messages', id:'content-inbox', hashid:'inbox', langid:'SUB_NAVIGATION_ITEM_INBOX', control:[], submenu:[]}, //Inbox
		{tab:'messages', id:'content-sent', hashid:'sent', langid:'SUB_NAVIGATION_ITEM_SENT', control:[], submenu:[]}, //Sent
		{tab:'messages', id:'content-outbox', hashid:'outbox', langid:'SUB_NAVIGATION_ITEM_OUTBOX', control:[], submenu:[]}, //Outbox
		*/
      //settings
      {
        tab: "settings",
        id: "password",
        hashid: "60",
        langid: "905001",
        control: [],
        submenu: [],
      }, //Password
      {
        tab: "settings",
        id: "vodafone_safe_netwok",
        hashid: "vodafone_safe_netwok",
        langid: "SUB_NAVIGATION_ITEM_VODAFONE_SAFE_NETWORK",
        control: ["sys_vodafone_safe_netwok"],
        submenu: [],
      }, //Safe Network
      {
        tab: "settings",
        id: "firmware-update",
        hashid: "59",
        langid: "905002",
        control: [],
        submenu: [],
      }, //Firmware Update
      {
        tab: "settings",
        id: "energy-settings",
        hashid: "55",
        langid: "PAGE_ENERGY_SETTINGS_TITLE",
        control: ["show_settings_energysettings"],
        submenu: [],
      }, //Energy Settings
      {
        tab: "settings",
        id: "usb",
        hashid: "58",
        langid: "905003",
        control: ["sys_usb_status"],
        submenu: [],
      }, //USB
      {
        tab: "settings",
        id: "content-sharing",
        hashid: "56",
        langid: "SUB_NAVIGATION_ITEM_CONTENT_SHARING",
        control: ["sys_usb_status"],
        submenu: [
          //Content Sharing
          {
            tab: "settings",
            id: "dlna",
            hashid: "57",
            langid: "905004",
            control: ["sys_usb_status"],
            submenu: [],
          }, //DLNA
          {
            tab: "settings",
            id: "network-share-samba",
            hashid: "51",
            langid: "SUB_SUB_NAVIGATION_ITEM_NETWORK_SHARE_SAMBA",
            control: ["sys_usb_status"],
            submenu: [],
          }, //Samba
          {
            tab: "settings",
            id: "ftp",
            hashid: "50",
            langid: "905011",
            control: ["sys_usb_status"],
            submenu: [],
          }, //FTP
          {
            tab: "settings",
            id: "upnp",
            hashid: "85",
            langid: "315001",
            control: ["sys_usb_status"],
            submenu: [],
          }, //UPnP
        ],
      },
      {
        tab: "settings",
        id: "printer-sharing",
        hashid: "83",
        langid: "521001",
        control: ["sys_usb_status", "show_settings_printersharing"],
        submenu: [],
      }, //Printer Sharing
      {
        tab: "settings",
        id: "configuration",
        hashid: "54",
        langid: "905007",
        control: [],
        submenu: [],
      }, //Configuration
      {
        tab: "settings",
        id: "lan",
        hashid: "52",
        langid: "905009",
        control: [],
        submenu: [],
      }, //LAN
      {
        tab: "settings",
        id: "qos",
        hashid: "73",
        langid: "905018",
        control: [],
        submenu: [
          //QoS
          // peter 08/17 '18 {tab:'settings', id:'rate_limit', hashid:'rate_limit', langid:'1301901', control:[], submenu:[]} //Rate Limit
        ],
      },
      {
        tab: "settings",
        id: "internet-time",
        hashid: "74",
        langid: "513001",
        control: [],
        submenu: [],
      }, //Internet Time
      {
        tab: "settings",
        id: "tr-069",
        hashid: "75",
        langid: "905019",
        control: [],
        submenu: [],
      }, //TR-069
      {
        tab: "settings",
        id: "snmp",
        hashid: "76",
        langid: "905020",
        control: ["show_settings_snmp"],
        submenu: [],
      }, //SNMP
      {
        tab: "settings",
        id: "settings-access-control",
        hashid: "80",
        langid: "906017",
        control: [],
        submenu: [],
      }, //Access control
      {
        tab: "settings",
        id: "xdsl",
        hashid: "90",
        langid: "903017",
        control: ["show_settings_xdsl"],
        submenu: [],
      }, //xDSL
      {
        tab: "settings",
        id: "wan",
        hashid: "92",
        langid: "903013",
        control: [],
        submenu: [],
      }, //WAN
      {
        tab: "settings",
        id: "ipv6-basic-configuration",
        hashid: "97",
        langid: "905023",
        control: ["sys_ipv6_status"],
        submenu: [],
      }, //IPv6 Basic Configuration
      {
        tab: "settings",
        id: "static-routing",
        hashid: "86",
        langid: "522001",
        control: [],
        submenu: [],
      }, //Static Routing
      {
        tab: "settings",
        id: "policy-routing",
        hashid: "93",
        langid: "903018",
        control: [],
        submenu: [],
      }, //Policy Routing
      //{tab:'settings', id:'gpon', hashid:'109', langid:'1301500', control:[], submenu:[]}, //GPON
      {
        tab: "settings",
        id: "lan_switch",
        hashid: "lan_switch",
        langid: "1301701",
        control: [],
        submenu: [],
      }, //lan switch
      {
        tab: "settings",
        id: "iptv",
        hashid: "108",
        langid: "903019",
        control: ["sys_iptv_status"],
        submenu: [],
      }, //TV Settings
      {
        tab: "settings",
        id: "igmp_proxy",
        hashid: "igmp_proxy",
        langid: "1301462",
        control: [],
        submenu: [],
      }, //igmp proxy
      {
        tab: "settings",
        id: "umts-settings",
        hashid: "88",
        langid: "1301442",
        control: ["sys_umts_status", "show_settings_mobile"],
        submenu: [],
      }, //Mobile
      {
        tab: "settings",
        id: "sfp-reg-id",
        hashid: "sfp-reg-id",
        langid: "SUB_NAVIGATION_ITEM_SFP_REG_ID",
        control: ["sys_sfp_status"],
        submenu: [],
      }, //SFP REG ID
      {
        tab: "settings",
        id: "openmodem",
        hashid: "openmodem",
        langid: "SUB_NAVIGATION_ITEM_GENERIC_MODEM",
        control: ["sys_openmodem_status"],
        submenu: [
          //Open Modem
          //{tab:'settings', id:'openmodem_wan', hashid:'openmodem_wan', langid:'903013', control:["sys_openmodem_status"], submenu:[]}, //WAN
          {
            tab: "settings",
            id: "openmodem_internet_time",
            hashid: "openmodem_internet_time",
            langid: "513001",
            control: ["sys_openmodem_status", "sys_openmodem_subpages_status"],
            submenu: [],
          }, //Internet Time
          {
            tab: "settings",
            id: "openmodem_phone_settings",
            hashid: "openmodem_phone_settings",
            langid: "SUB_SUB_NAVIGATION_ITEM_PHONE_SETTINGS",
            control: ["sys_openmodem_status", "sys_openmodem_subpages_status"],
            submenu: [],
          }, //Phone Settings
        ],
      },
      //status-and-support
      {
        tab: "status-and-support",
        id: "status",
        hashid: "1",
        langid: "906001",
        control: [],
        submenu: [
          //Status
          {
            tab: "status-and-support",
            id: "voice_status",
            hashid: "3",
            langid: "906003",
            control: [],
            submenu: [],
          }, //Voice Status
          {
            tab: "status-and-support",
            id: "vdsl_status",
            hashid: "66",
            langid: "1300081",
            control: ["show_ss_vdsl"],
            submenu: [],
          }, //VDSL Status
          {
            tab: "status-and-support",
            id: "fibre_status",
            hashid: "82",
            langid: "907003",
            control: ["show_ss_fibre"],
            submenu: [],
          }, //Fibre Statuss
          {
            tab: "status-and-support",
            id: "wan_status",
            hashid: "67",
            langid: "906013",
            control: [],
            submenu: [],
          }, //WAN Status
          {
            tab: "status-and-support",
            id: "optical_status",
            hashid: "201",
            langid: "1301726",
            control: [],
            submenu: [],
          }, //Optical Status
          {
            tab: "status-and-support",
            id: "lan_status",
            hashid: "70",
            langid: "906014",
            control: [],
            submenu: [],
          }, //LAN Status
          {
            tab: "status-and-support",
            id: "gpon_status",
            hashid: "gpon_status",
            langid: "1301761",
            control: [],
            submenu: [],
          }, //GPON Status
          {
            tab: "status-and-support",
            id: "dongle-connectivity",
            hashid: "dongle-connectivity",
            langid: "SUB_SUB_NAVIGATION_ITEM_DONGLE_CONNECTIVITY",
            control: ["sys_umts_status"],
            submenu: [],
          }, //Dongle Connectivity
          {
            tab: "status-and-support",
            id: "iptv_status",
            hashid: "202",
            langid: "1301749",
            control: [],
            submenu: [],
          }, //iptv status
          {
            tab: "status-and-support",
            id: "routing_status",
            hashid: "71",
            langid: "906015",
            control: [],
            submenu: [],
          }, //Routing
          {
            tab: "status-and-support",
            id: "umts_status",
            hashid: "44",
            langid: "1301451",
            control: ["sys_umts_status", "show_ss_mobile"],
            submenu: [],
          }, //Mobile Status
        ],
      },
      {
        tab: "status-and-support",
        id: "diagnostic-utility",
        hashid: "4",
        langid: "906004",
        control: [],
        submenu: [
          //Diagnostic Utility
          {
            tab: "status-and-support",
            id: "gpon-debug",
            hashid: "110",
            langid: "1301511",
            control: [],
            submenu: [],
          }, //GPON Debug
          // peter 08/16 '18 {tab:'status-and-support', id:'trabsceuver_debug', hashid:'203', langid:'1301557', control:[], submenu:[]}, //Transceiver Debug
          {
            tab: "status-and-support",
            id: "voip-diagnostics",
            hashid: "87",
            langid: "616001",
            control: [],
            submenu: [],
          }, //VOIP Diagnostics
          // peter 08/16 '18 {tab:'status-and-support', id:'packet_trace', hashid:'204', langid:'1301943', control:[], submenu:[]}, //Packet Trace
          //{tab:'status-and-support', id:'trace_route', hashid:'205', langid:'1301958', control:[], submenu:[]}, //Trace Route
          {
            tab: "status-and-support",
            id: "debug_log",
            hashid: "debug_log",
            langid: "1101008",
            control: [],
            submenu: [],
          }, //Debug Log
          {
            tab: "status-and-support",
            id: "port-mirroring",
            hashid: "98",
            langid: "906019",
            control: [],
            submenu: [],
          }, //Port Mirroring
        ],
      },
      {
        tab: "status-and-support",
        id: "event-log",
        hashid: "6",
        langid: "906006",
        control: [],
        submenu: [],
      }, //Event Log
      {
        tab: "status-and-support",
        id: "restart",
        hashid: "41",
        langid: "906007",
        control: [],
        submenu: [],
      }, //Restart
      {
        tab: "status-and-support",
        id: "nat-mapping-table",
        hashid: "28",
        langid: "903007",
        control: [],
        submenu: [],
      }, //NAT Mapping Table
      {
        tab: "status-and-support",
        id: "about",
        hashid: "42",
        langid: "906008",
        control: [],
        submenu: [],
      }, //About
    ];
  }

  return navigation;
}

function chkPageSelect(page, dropDownBasExp) {
  var reloadPage = false;

  var locationInfo = window.location.toString().split("#");
  var pageId = locationInfo[1];
  if (typeof pageId == "undefined") {
    reloadPage = true;
  }

  if (page != "overview") {
    var navigation = navigation_init(page, dropDownBasExp);
    var ary_sub_page = _getMenuItemList(page, "sub=", navigation);
    //if(logMessage && window.console) console.log(ary_sub_page);

    if (page == "phone") {
      if (!in_array(pageId, ary_sub_page)) {
        pageId = "sub=7";
        reloadPage = true;
      }
    }
    if (page == "internet") {
      if (dropDownBasExp == "admin") {
        if (!in_array(pageId, ary_sub_page)) {
          pageId = "sub=22";
          reloadPage = true;
        }
      } else {
        if (!in_array(pageId, ary_sub_page)) {
          if (ary_sub_page !== undefined) {
            if (ary_sub_page.length > 0) {
              pageId = ary_sub_page[0];
              reloadPage = true;
            } else {
              pageId = "";
              reloadPage = true;
            }
          } else {
            pageId = "";
            reloadPage = true;
          }
        }
      }
    }
    if (page == "wifi") {
      if (!in_array(pageId, ary_sub_page)) {
        pageId = "sub=35";
        reloadPage = true;
      }
    }
    if (page == "messages") {
      if (!in_array(pageId, ary_sub_page)) {
        pageId = "sub=create_message";
        reloadPage = true;
      }
    }
    if (page == "sharing") {
      if (!in_array(pageId, ary_sub_page)) {
        pageId = "sub=sharing";
        reloadPage = true;
      }
    }
    if (page == "settings") {
      if (!in_array(pageId, ary_sub_page)) {
        pageId = "sub=60";
        reloadPage = true;
      }
    }
    if (page == "status-and-support") {
      if (!in_array(pageId, ary_sub_page)) {
        pageId = "sub=1";
        reloadPage = true;
      }
    }

    sys_pageid = pageId;
    if (reloadPage) {
      window.parent.location = locationInfo[0] + "#" + pageId;
    }
  } else {
    sys_pageid = pageId;
  }
}

function header_init(page, dropDownBasExp, items) {
  var html_out = "";
  html_out += '<div class="rel">';
  html_out += '<div id="top-bar">';
  html_out += '<div id="top-bar-content">';
  html_out += '<div class="rel">';
  html_out += '<a href="overview.html" tid="0" al="1300068">';
  html_out += '<div id="logo">' + getHTMLString(1300068) + "</div>"; //VFH 500
  html_out += "</a>";
  html_out += '<div id="top-info" class="clearfix">';
  html_out += '<div id="top-info-mode" class="rel">';
  html_out += '<div id="logout" style="display: none;">&nbsp;</div>';
  html_out +=
    '<select class="dropdown" style="width: 165px; display: none;" tid="0" al="SELECTBOX">';
  if (dropDownBasExp !== "admin") {
    if (dropDownBasExp == "basic") {
      html_out +=
        '<option value="basic" selected="selected">' +
        getHTMLString("GATEWAY_MODE_BASIC") +
        "</option>"; //Basic Mode
    } else {
      html_out +=
        '<option value="basic">' +
        getHTMLString("GATEWAY_MODE_BASIC") +
        "</option>"; //Basic Mode
    }
    if (dropDownBasExp == "expert") {
      html_out +=
        '<option value="expert" selected="selected">' +
        getHTMLString("GATEWAY_MODE_EXPERT") +
        "</option>"; //Expert Mode
    } else {
      html_out +=
        '<option value="expert">' +
        getHTMLString("GATEWAY_MODE_EXPERT") +
        "</option>"; //Expert Mode
    }
  } else {
    html_out +=
      '<option value="admin" selected="selected">' +
      getHTMLString("GATEWAY_MODE_ADMIN") +
      "</option>"; //Admin Mode
  }
  html_out += '<option value="logout">Logout</option>'; //Logout
  html_out += "</select>";
  html_out += "</div>";
  html_out += '<div id="top-info-logged-user">';
  html_out +=
    '<div class="page-loader-container load-once" tid="0" al="' +
    getHTMLString(1310021).replace("%s", sys_logged_in_users) +
    '">' +
    getHTMLString(1310021).replace(
      "%s",
      "<strong>" + sys_logged_in_users + "</strong>",
    ) +
    "</div>";
  html_out += "</div>";
  html_out += "</div>";
  html_out += "</div>";
  html_out += "</div>";
  html_out += "</div>";
  html_out += '<div id="rhombus-navigation" class="clearfix">';
  html_out += '<div class="rel">';
  html_out += '<div id="navigation">';
  html_out += '<ul class="clearfix">';
  for (var key in items) {
    if (items[key] === "overview") {
      html_out +=
        '<li style="min-width: 110px;"><a href="overview.html" tid="0" al="700031"><span id="lang700031" class="noEAA">' +
        getHTMLString(700031) +
        "</span></a></li>"; //Overview
    } else if (items[key] === "phone") {
      html_out +=
        '<li><a href="phone.html#sub=7" onclick="page_data_load(\'phone\');" tid="0" al="700032"><span id="lang700032" class="noEAA">' +
        getHTMLString(700032) +
        "</span></a></li>"; //Phone
    } else if (items[key] === "internet") {
      if (dropDownBasExp !== "admin") {
        html_out +=
          '<li><a href="internet.html#sub=89" onclick="page_data_load(\'internet\');" tid="0" al="700033"><span id="lang700033" class="noEAA">' +
          getHTMLString(700033) +
          "</span></a></li>"; //Internet
      } else {
        html_out +=
          '<li><a href="internet.html#sub=22" onclick="page_data_load(\'internet\');" tid="0" al="700033"><span id="lang700033" class="noEAA">' +
          getHTMLString(700033) +
          "</span></a></li>"; //Internet
      }
    } else if (items[key] === "wifi") {
      html_out +=
        '<li><a href="wifi.html#sub=35" onclick="page_data_load(\'wifi\');" tid="0" al="700034"><span id="lang700034" class="noEAA">' +
        getHTMLString(700034) +
        "</span></a></li>"; //Wi-Fi
    } else if (items[key] === "messages") {
      html_out +=
        '<li><a href="messages.html#sub=create_message" onclick="page_data_load(\'messages\');" tid="0" al="NAVIGATION_ITEM_MESSAGES"><span name="NAVIGATION_ITEM_MESSAGES" class="noEAA">' +
        getHTMLString("NAVIGATION_ITEM_MESSAGES") +
        "</span></a></li>"; //Messages
    } else if (items[key] === "sharing") {
      html_out +=
        '<li><a href="sharing.html#sub=sharing" onclick="page_data_load(\'sharing\');" tid="0" al="PAGE_SHARING_TITLE"><span name="PAGE_SHARING_TITLE" class="noEAA">' +
        getHTMLString("PAGE_SHARING_TITLE") +
        "</span></a></li>"; //Sharing
    } else if (items[key] === "settings") {
      html_out +=
        '<li><a href="settings.html#sub=60" onclick="page_data_load(\'settings\');" tid="0" al="700035"><span id="lang700035" class="noEAA">' +
        getHTMLString(700035) +
        "</span></a></li>"; //Settings
    } else if (items[key] === "status-and-support") {
      html_out +=
        '<li><a href="status-and-support.html#sub=1" onclick="page_data_load(\'status-and-support\');" tid="0" al="700036"><span id="lang700036" class="noEAA">' +
        getHTMLString(700036) +
        "</span></a></li>"; //Status &amp; Support
    }
  }
  html_out += "</ul>";
  html_out += "</div>";
  html_out += "</div>";
  html_out += "</div>";
  html_out += "</div>";
  $("#header").html(html_out);
}

function navigation_init(page, dropDownBasExp) {
  var navigation = [];
  if (dropDownBasExp == "basic") {
    navigation = _obj_navigation_basic();
  } else if (dropDownBasExp == "expert") {
    navigation = _obj_navigation_expert();
  } else if (dropDownBasExp == "admin") {
    navigation = _obj_navigation_admin();
  }

  return navigation_init_check(navigation);
}

function navigation_init_check(obj) {
  var tmp_navigation = [];
  for (var key in obj) {
    if (_chkNavigationControl(obj[key].control)) {
      tmp_navigation.push(obj[key]);
      if (obj[key].submenu.length > 0) {
        tmp_navigation[tmp_navigation.length - 1].submenu =
          navigation_init_check(obj[key].submenu);
      }
    }
  }

  return tmp_navigation;
}

function navigation_items_init(ary) {
  var ret_ary = ["overview"];
  for (var key in ary) {
    if (ret_ary[ret_ary.length - 1] !== ary[key].tab) {
      ret_ary.push(ary[key].tab);
    }
  }

  return ret_ary;
}

function _makeNavigation(obj, items) {
  var html = "";
  for (var key in items) {
    if (items[key] === "overview") {
      //overview
      html +=
        '<div class="subnavigation-' +
        (parseInt(key, 10) + 1) +
        "of" +
        items.length +
        '">';
      html += '<ul class="sub-navigation">';
      html += '<li class="sub-navigation-item navigation-item">';
      html +=
        '<a class="sub-navigation-item-title" tid="0" al="700031">' +
        getHTMLString(700031) +
        "</a>"; //Overview
      html += "</li>";
      html += "</ul>";
      html += "</div>";
    } else {
      //others
      html +=
        '<div class="subnavigation-' +
        (parseInt(key, 10) + 1) +
        "of" +
        items.length +
        '">';
      html += _makeMenuItem(items[key], obj);
      html += "</div>";
    }
  }

  return html;
}

function _makeMenuItem(page, obj) {
  var html = "";
  html += '<ul class="sub-navigation">';
  for (var key in obj) {
    if (obj[key].tab === page && _chkNavigationControl(obj[key].control)) {
      if (obj[key].submenu.length > 0) {
        html +=
          '<li id="' +
          obj[key].hashid +
          '" class="sub-navigation-item navigation-item subnavigation-has-sub-sub">';
      } else {
        html +=
          '<li id="' +
          obj[key].hashid +
          '" class="sub-navigation-item navigation-item">';
      }
      html +=
        '<a href="#sub=' +
        obj[key].hashid +
        '" onclick="page_data_load(\'' +
        obj[key].tab +
        '\');" class="sub-navigation-item-title" tid="0" alm="' +
        getHTMLString(obj[key].langid) +
        '">' +
        getHTMLString(obj[key].langid) +
        "</a>";
      if (obj[key].submenu.length > 0) {
        html += _makeSubMenuItem(page, obj[key].hashid, obj[key].submenu);
      }
      html += "</li>";
    }
  }
  html += "</ul>";

  return html;
}

function _makeSubMenuItem(page, hashid, obj) {
  var html = "";
  html += '<ul class="sub-sub-navigation">';
  for (var key in obj) {
    if (obj[key].tab === page && _chkNavigationControl(obj[key].control)) {
      html +=
        '<li id="' +
        obj[key].hashid +
        '" class="sub-sub-navigation-item navigation-item">';
      html +=
        '<a href="#sub=' +
        hashid +
        "&subSub=" +
        obj[key].hashid +
        '" onclick="page_data_load(\'' +
        obj[key].tab +
        '\');" class="sub-sub-navigation-item-title" tid="0" alm="' +
        getHTMLString(obj[key].langid) +
        '">' +
        getHTMLString(obj[key].langid) +
        "</a>";
      html += "</li>";
    }
  }
  html += "</ul>";

  return html;
}

function _chkNavigationControl(control) {
  var ret_val = true;
  for (var key in control) {
    if (this[control[key]] !== true) {
      ret_val = false;
    }
  }

  return ret_val;
}

function _getMenuItemList(page, prestr, obj) {
  var ret_ary = [];
  for (var key in obj) {
    if (obj[key].tab === page && _chkNavigationControl(obj[key].control)) {
      ret_ary.push(prestr + obj[key].hashid);

      if (obj[key].submenu.length > 0) {
        ret_ary = ret_ary.concat(
          _getMenuItemList(
            page,
            prestr + obj[key].hashid + "&subSub=",
            obj[key].submenu,
          ),
        );
      }
    }
  }

  return ret_ary;
}

function mobile_header_init(page, dropDownBasExp, navigation, items) {
  var html_out = "";
  html_out += '<div class="rel">';
  html_out += '<div class="mobile-header-style">';
  html_out += '<div class="hamburger-menu" tid="0" al="Menu">';
  html_out += "<span></span>";
  html_out += "<span></span>";
  html_out += "<span></span>";
  html_out += "</div>";
  html_out += "</div>";
  html_out += '<div class="product-name">';
  html_out +=
    '<h3><span tid="0" al="1300068">' + getHTMLString(1300068) + "</span></h3>";
  html_out += "</div>";
  html_out += '<div class="menu">';
  html_out += '<ul class="clearfix mobile-navigation">';
  html_out += _makeMobileNavigation(navigation, page, items);
  html_out += "</ul>";
  html_out += "</div>";
  html_out += '<div class="mobile-menu-bottom">';
  html_out += '<div class="bottom-info">';
  html_out +=
    '<div class="page-loader-container load-once" tid="0" alm="' +
    getHTMLString("PAGE_TOP_INFO_USER_LOGGED_IN").replace(
      "%s",
      sys_logged_in_users,
    ) +
    '">' +
    getHTMLString("PAGE_TOP_INFO_USER_LOGGED_IN").replace(
      "%s",
      "<strong>" + sys_logged_in_users + "</strong>",
    ) +
    "</div>";
  html_out += "</div>";
  html_out += '<div class="mode-menu">';
  html_out +=
    '<select class="dropdown" style="width: 165px;" tid="0" al="SELECTBOX">';
  if (dropDownBasExp !== "admin") {
    if (dropDownBasExp == "basic") {
      html_out +=
        '<option value="basic" selected="selected">' +
        getHTMLString("GATEWAY_MODE_BASIC") +
        "</option>"; //Basic Mode
    } else {
      html_out +=
        '<option value="basic">' +
        getHTMLString("GATEWAY_MODE_BASIC") +
        "</option>"; //Basic Mode
    }
    if (dropDownBasExp == "expert") {
      html_out +=
        '<option value="expert" selected="selected">' +
        getHTMLString("GATEWAY_MODE_EXPERT") +
        "</option>"; //Expert Mode
    } else {
      html_out +=
        '<option value="expert">' +
        getHTMLString("GATEWAY_MODE_EXPERT") +
        "</option>"; //Expert Mode
    }
  } else {
    html_out +=
      '<option value="admin" selected="selected">' +
      getHTMLString("GATEWAY_MODE_ADMIN") +
      "</option>"; //Admin Mode
  }
  html_out += "</select>";
  html_out += "</div>";
  html_out += '<div class="logout">';
  html_out += '<a class="mobile_logout" tid="0" alm="Logout">Logout</a>';
  html_out += "</div>";
  html_out += "</div>";
  html_out += "</div>";

  $("#mobile-menu-overlay").html(html_out);
}

function _makeMobileNavigation(obj, page, items) {
  var html = "";
  for (var key in items) {
    if (items[key] === "overview") {
      //overview
      if (page === "overview") {
        html +=
          '<li class="main-item mobile-navigation-item-' +
          (parseInt(key, 10) + 1) +
          ' first-item active">';
      } else {
        html +=
          '<li class="main-item mobile-navigation-item-' +
          (parseInt(key, 10) + 1) +
          ' first-item">';
      }
      html +=
        '<a href="overview.html" class="mobile-navigation-item-title" tid="0" al="700031">' +
        getHTMLString(700031) +
        "</a>"; //Overview
      html += '<div class="expand-mobile-sub">';
      html += "<span></span>";
      html += "<span></span>";
      html += "</div>";
      //html += '<ul class="mobile-sub-navigation">';
      //html += '<li class="mobile-sub-navigation-item mobile-navigation-item">';
      //html += '<a class="mobile-sub-navigation-item-title">'+getHTMLString(700031)+'</a>'; //Overview
      //html += '</li>';
      //html += '</ul>';
      html += "</li>";
    } else {
      if (page === items[key]) {
        html +=
          '<li class="main-item mobile-navigation-item-' +
          (parseInt(key, 10) + 1) +
          ' active">';
      } else {
        html +=
          '<li class="main-item mobile-navigation-item-' +
          (parseInt(key, 10) + 1) +
          '">';
      }

      if (items[key] === "phone") {
        html +=
          '<a class="mobile-navigation-item-title" tid="0" al="700032">' +
          getHTMLString(700032) +
          "</a>"; //Phone
      } else if (items[key] === "internet") {
        html +=
          '<a class="mobile-navigation-item-title" tid="0" al="700033">' +
          getHTMLString(700033) +
          "</a>"; //Internet
      } else if (items[key] === "wifi") {
        html +=
          '<a class="mobile-navigation-item-title" tid="0" al="700034">' +
          getHTMLString(700034) +
          "</a>"; //WiFi
      } else if (items[key] === "messages") {
        html +=
          '<a class="mobile-navigation-item-title" tid="0" al="NAVIGATION_ITEM_MESSAGES">' +
          getHTMLString("NAVIGATION_ITEM_MESSAGES") +
          "</a>"; //Messages
      } else if (items[key] === "sharing") {
        html +=
          '<a class="mobile-navigation-item-title" tid="0" al="PAGE_SHARING_TITLE">' +
          getHTMLString(PAGE_SHARING_TITLE) +
          "</a>"; //Sharing
      } else if (items[key] === "settings") {
        html +=
          '<a class="mobile-navigation-item-title" tid="0" al="700035">' +
          getHTMLString(700035) +
          "</a>"; //Settings
      } else if (items[key] === "status-and-support") {
        html +=
          '<a class="mobile-navigation-item-title" tid="0" al="700036">' +
          getHTMLString(700036) +
          "</a>"; //Status & Support
      }

      html += '<div class="expand-mobile-sub">';
      html += "<span></span>";
      html += "<span></span>";
      html += "</div>";
      html += _makeMobileMenuItem(page, items[key], obj);
      html += "</li>";
    }
  }

  return html;
}

function _makeMobileMenuItem(page, get_page, obj) {
  var html = "";
  html += '<ul class="mobile-sub-navigation">';
  for (var key in obj) {
    if (obj[key].tab === get_page && _chkNavigationControl(obj[key].control)) {
      if (obj[key].submenu.length > 0) {
        html +=
          '<li id="mobile_' +
          obj[key].hashid +
          '" class="mobile-sub-navigation-item mobile-navigation-item subnavigation-has-sub-sub">';
      } else {
        html +=
          '<li id="mobile_' +
          obj[key].hashid +
          '" class="mobile-sub-navigation-item mobile-navigation-item">';
      }

      if (page === get_page) {
        html +=
          '<a href="#sub=' +
          obj[key].hashid +
          '" onclick="page_data_load(\'' +
          obj[key].tab +
          '\');" class="mobile-sub-navigation-item-title" tid="0" alm="' +
          getHTMLString(obj[key].langid) +
          '">' +
          getHTMLString(obj[key].langid) +
          "</a>";
      } else {
        html +=
          '<a href="' +
          get_page +
          ".html#sub=" +
          obj[key].hashid +
          '" class="mobile-sub-navigation-item-title" tid="0" alm="' +
          getHTMLString(obj[key].langid) +
          '">' +
          getHTMLString(obj[key].langid) +
          "</a>";
      }

      if (obj[key].submenu.length > 0) {
        html += _makeMobileSubMenuItem(
          page,
          get_page,
          obj[key].hashid,
          obj[key].submenu,
        );
      }

      html += "</li>";
    }
  }
  html += "</ul>";

  return html;
}

function _makeMobileSubMenuItem(page, get_page, hashid, obj) {
  var html = "";
  html += '<ul class="mobile-sub-sub-navigation">';
  for (var key in obj) {
    if (obj[key].tab === get_page && _chkNavigationControl(obj[key].control)) {
      html +=
        '<li id="mobile_' +
        obj[key].hashid +
        '" class="mobile-sub-sub-navigation-item mobile-navigation-item">';

      if (page === get_page) {
        html +=
          '<a href="#sub=' +
          hashid +
          "&subSub=" +
          obj[key].hashid +
          '" onclick="page_data_load(\'' +
          obj[key].tab +
          '\');" class="mobile-sub-sub-navigation-item-title" tid="0" alm="' +
          getHTMLString(obj[key].langid) +
          '">' +
          getHTMLString(obj[key].langid) +
          "</a>";
      } else {
        html +=
          '<a href="' +
          get_page +
          ".html#sub=" +
          hashid +
          "&subSub=" +
          obj[key].hashid +
          '" class="mobile-sub-sub-navigation-item-title" tid="0" alm="' +
          getHTMLString(obj[key].langid) +
          '">' +
          getHTMLString(obj[key].langid) +
          "</a>";
      }

      html += "</li>";
    }
  }
  html += "</ul>";

  return html;
}

function rebuild_sub_natigation_menu(menu_top_selection, menu_sub_selection) {
  var dropDownBasExp = sys_dropDownBasExp;
  if (usermode == "admin") dropDownBasExp = usermode;

  var tmp_navigation = navigation_init(menu_top_selection, dropDownBasExp);
  var tmp_navigation_items = navigation_items_init(tmp_navigation);

  $("#subnavigation").html(
    _makeNavigation(tmp_navigation, tmp_navigation_items),
  );

  // selected menu item
  var next = $("#" + menu_sub_selection);
  next.addClass("active");
}
