<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html  id="Page" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="Pragma" content="no-cache" >
<meta http-equiv="X-UA-Compatible" content="IE=edge"/>
<link rel="stylesheet"  href='../../../Cuscss/frame.css?03fa5651e1972f71553184798' type='text/css'>
<script language="JavaScript" src="../../../resource/common/jquery.min.js?03fa5651e1972f71553184798"></script>
<script language="JavaScript" src="../../../Cusjs/ptvdfjs.js?03fa5651e1972f71553184798"></script>
<script language="JavaScript" src="../../../resource/english/bbspdes.html?03fa5651e1972f71553184798"></script>
<script language="javascript" src="../common/wanipv6state.asp"></script>
<script language="javascript" src="../common/wan_list_ptvdf.asp?176935"></script>
<script language="JavaScript" src="../../../resource/english/ampdes.html?03fa5651e1972f71553184798"></script>
<script>

var wanInfoAll = GetWanList();
var curIPv4Address = "--";
var curWanMacId = ""
var ChanInfo = '7,104';
WlanChannel2g = ChanInfo.split(',')[0];
WlanChannel5g = ChanInfo.split(',')[1];
var language = 'english';
var typeWord = 'TR181';
var multiLinkFT = '1' == '1';
var hideMultiLink = '0' == '1';
var isSupportMlo = (multiLinkFT && !hideMultiLink);

function GetLanguage(name) {
    return status_language[name]
}

for (var i = 0; i < wanInfoAll.length; i++) {
    if ((wanInfoAll[i].ServiceList.toUpperCase().indexOf("INTERNET") >= 0) && (wanInfoAll[i].Status.toUpperCase() == "UP")) {
        curWanMacId = wanInfoAll[i].MacId;
        curIPv4Address = wanInfoAll[i].IPAddress;
        break;
    }
}

var curIPv6Address = "--";
var curIPv6Prefix = "--";
if (curWanMacId != "") {
    var curIPv6AddressList = GetIPv6AddressList(curWanMacId);
    var curIPv6PrefixList = GetIPv6PrefixList(curWanMacId);
    if (curIPv6AddressList.length != 0) {
        curIPv6Address = curIPv6AddressList[0].IPAddress;
    }
    if (curIPv6PrefixList.length != 0) {
        curIPv6Prefix = curIPv6PrefixList[0].Prefix;
    }
}

function stLanHostInfo(domain, IPInterfaceIPAddress, IPInterfaceSubnetMask) {
    this.domain = domain;
    this.IPAddress = IPInterfaceIPAddress;
    this.SubnetMask = IPInterfaceSubnetMask;
}

function stMainDhcpInfo(domain, DHCPServerEnable, MACAddress) {
    this.domain = domain;
    this.DHCPServerEnable = DHCPServerEnable;
    this.MACAddress = MACAddress;
}
function IPAddressAcquireIPItem(_domain, _DefaultGateway) {
    this.domain = _domain;
    this.DefaultGateway = _DefaultGateway;
}

function IPAddressAcquirePPPItem(_domain, _DefaultGateway) {
    this.domain = _domain;
    this.DefaultGateway = _DefaultGateway;
}

var IPAddressAcquireIP  = new Array(new IPAddressAcquireIPItem("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.X_HW_IPv6.IPv6Address.1",""),null);
var IPAddressAcquirePPP = new Array(null);
var IPAddressAcquireList = truncate(IPAddressAcquireIP).concat(truncate(IPAddressAcquirePPP));
var lanHostInfos = new Array(new stLanHostInfo("InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1","192.0.2.2","255.255.255.0"),null);
var lanHostInfo = lanHostInfos[0];
var mainDhcpInfos = new Array(new stMainDhcpInfo("InternetGatewayDevice.LANDevice.1.LANHostConfigManagement","0","00:11:22:33:44:01"),null);
var mainDhcpInfo = mainDhcpInfos[0];
var dhcpv6ServerEnable = '1'
var dhcpv6RouteEnable = '1'

var cpuUsed = '24%';
var memUsed = '12%';
var systemdsttime = '2026-08-09 12:25:11+00:00 DST';

function stDeviceInfo(domain,SerialNumber,HardwareVersion,SoftwareVersion,Description,UpTime)
{
    this.domain                = domain;
    this.SerialNumber          = SerialNumber;
    this.HardwareVersion       = HardwareVersion;
    this.SoftwareVersion       = SoftwareVersion;
    this.Description           = Description;
    this.UpTime                = UpTime;
}

function CreatStatusInfoTable(tableTitle, tableID, tableArrayInfo, tablewidth) {
    var htmlinfo = '<div id="' + tableID + '" style="margin-bottom:50px;">';
    if (tableTitle != "" && tableTitle != null) {
        htmlinfo += '<h3><span class="language-string">' + tableTitle + '</span></h3>';
    }
    htmlinfo += '<div class="h3-wrapper-content no-padding-bottom">';
    htmlinfo += '<div class="table desktop" style="font-size: 13px;text-align: center;">';
    for (var m = 0; m < tableArrayInfo.length; m++) {
        var lastclass = (m == tableArrayInfo.length - 1) ? "table-row" : "table-row bottomline";
        htmlinfo += '<div class="' + lastclass + '">';
        for (var n = 0; n < tableArrayInfo[m].length; n++) {
            if ((typeof tablewidth == "undefined") || (tablewidth == "") || (tablewidth == null)) {
                htmlinfo += '<div class="table-col-status" style="width:' + (100/tableArrayInfo[0].length) + '%;">' + changetospace(escapeHTML(tableArrayInfo[m][n])) + '</div>';
            } else {
                htmlinfo += '<div class="table-col-status" style="width:' + tablewidth[n] + '%;">' + changetospace(escapeHTML(tableArrayInfo[m][n])) + '</div>';
            }
        }
        htmlinfo +='</div>';
    }
    htmlinfo +='</div>';
    htmlinfo +='</div>';
    htmlinfo +='</div>';
    document.write(htmlinfo);
}

function LanPortStatus(domain,Status,Speed)
{
    this.domain	= domain;
    this.Status = Status; 
    this.Speed 	= Speed; 

    if(Status=='Up')
    {
        if(Speed=='Auto_10')this.Speed = 10;
        if(Speed=='Auto_100')this.Speed = 100;
        if(Speed=='Auto_1000')this.Speed = 1000;
        if(Speed=='Auto_2500')this.Speed = 2500;
        this.Status = status_LANnetwork_language['amp_lan_port_on'];
    }
    else
    {
        this.Speed = 0;
        this.Status = status_LANnetwork_language['amp_lan_port_off'];
    }
    
}
function getSameIPandMask(ipAddress, subnetMask) {
    var maskStr ="";
    var IPStrArr = [];
    var tmpMask = subnetMask.split('.');
    var tmpIp = ipAddress.split('.');
    for (var maskLenNum = 0; maskLenNum < 4; maskLenNum++) {
        tmpNum0 = parseInt(tmpIp[maskLenNum]);
        tmpNum1 = parseInt(tmpMask[maskLenNum]);
        tmpNum2 = tmpNum0 & tmpNum1;
        IPStrArr.push(tmpNum2)
    }
    for (let i = 0; i < tmpMask.length; i++) {
        if (tmpMask[i] != "0") {
            maskStr += parseInt(tmpMask[i]).toString(2)
        } else {
            continue;
        }
    }
    return IPStrArr.join(".") + "/" + maskStr.length;
}
var LanPortStatuss = new Array(new LanPortStatus("InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1","Up","Auto_1000"),new LanPortStatus("InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.2","Down","Auto_10"),new LanPortStatus("InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.3","Down","Auto_10"),new LanPortStatus("InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.4","Down","Auto_10"),null);
var deviceInfos = new Array(new stDeviceInfo("InternetGatewayDevice.DeviceInfo","TESTSERIAL00000001","3F80.A","V5R024C00S114","OptiXstar HG8247B7-8N GPON Terminal (CLASS B+/PRODUCT ID:0000000000000000000EGR0000000)","176935"),null);
var wantableArr = new Array();
wantableArr.push([GetLanguage("status006"), curIPv4Address, ""]);
wantableArr.push([GetLanguage("status007"), curIPv6Address, ""]);
wantableArr.push([GetLanguage("status008"), curIPv6Prefix, ""]);

var lantableArr = new Array();

lantableArr.push([GetLanguage("status009"), getSameIPandMask(lanHostInfo.IPAddress, lanHostInfo.SubnetMask), ""]);
lantableArr.push([GetLanguage("status010"), lanHostInfo.IPAddress, ""]);
lantableArr.push([GetLanguage("status012"), mainDhcpInfo.MACAddress, ""]);
if (typeWord != "BR") {
    lantableArr.push([GetLanguage("status013"), getStatus(mainDhcpInfo.DHCPServerEnable), ""]);
    lantableArr.push([GetLanguage("status014"), getStatus(dhcpv6ServerEnable), ""]);
    lantableArr.push([GetLanguage("status015"), getStatus(dhcpv6RouteEnable), ""]);

    var ipv6Wan = GetIPv6WanInfo(curWanMacId)
    if ((ipv6Wan == null) || (ipv6Wan == "")) {
        lantableArr.push([GetLanguage("status016"), "--", ""]);
    } else {
        lantableArr.push([GetLanguage("status016"), ipv6Wan.DefaultRouterAddress, ""]);
    }
}

var lanid;
for(var i = 0; i < LanPortStatuss.length - 1; i++)
{
    lanid = i + 1;
    lantableArr.push([GetLanguage("status030") + lanid, LanPortStatuss[i].Status, LanPortStatuss[i].Speed + ' Mbps']);
}

var WlanInfo = new Array();
WlanInfo = new Array(new stWlan("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1","1","ath0","Vodafone-21AF54","11i","7","00:11:22:33:44:02","Up"),new stWlan("InternetGatewayDevice.LANDevice.1.WLANConfiguration.2","0","ath1","Vodafone-21AF54-Guest","11i","7","00:11:22:33:44:03","Down"),new stWlan("InternetGatewayDevice.LANDevice.1.WLANConfiguration.3","0","ath2","Vodafone-21AF54_WiFi7","WPA3","7","00:11:22:33:44:04","Down"),new stWlan("InternetGatewayDevice.LANDevice.1.WLANConfiguration.4","0","ath6","Vodafone-21AF54_WiFi7","WPA3","104","00:11:22:33:44:05","Down"),new stWlan("InternetGatewayDevice.LANDevice.1.WLANConfiguration.5","1","ath4","Vodafone-21AF54","11i","104","00:11:22:33:44:06","Up"),new stWlan("InternetGatewayDevice.LANDevice.1.WLANConfiguration.6","0","ath5","Vodafone-21AF54-Guest","11i","104","00:11:22:33:44:07","Down"),null);  
for (var i = 0; i <  WlanInfo.length; i++) {
    if (WlanInfo[i] == null) {
        WlanInfo.splice(i,1);
    }
}
var wifi2G = new Array();
var wifi5G = new Array();
var wifi7for2G = {};
var wifi7for5G = {};

for (var i = 0; i < WlanInfo.length; i++) {
    if (WlanInfo[i].Name == 'ath0') {
        wifi2G = WlanInfo[i];
    } else if (WlanInfo[i].Name == 'ath4') {
        wifi5G = WlanInfo[i];
    } else if (isSupportMlo && (WlanInfo[i].Name == 'ath2')) {
      wifi7for2G = WlanInfo[i];
    } else if (isSupportMlo && (WlanInfo[i].Name == 'ath6')) {
      wifi7for5G = WlanInfo[i];
    }
}

function stWlan(domain, Enable, Name, SSID, BeaconType, Channel, BSSID, SSIDStatus) {
    this.domain = domain;
    this.Enable = Enable;
    this.Name = Name;
    this.SSID = SSID;
    this.BeaconType = BeaconType;
    this.Channel = Channel;
    this.BSSID = BSSID;
    this.SSIDStatus = SSIDStatus;
}

function GetWifiStatus(enable) {
    if ((enable == undefined) || (enable.toUpperCase() == "DOWN")) {
        return "Off";
    }
    if (language.toUpperCase() == "PORTUGUESE") {
        return "Ativo";
    } else {
        return "On";
    }
}

function GetBeaconType(beacontype) {
    if (beacontype == 'Basic') {
        return "Off";
    } else if (beacontype == 'WPA') {
        return "WPA";
    } else if ((beacontype == '11i') || (beacontype == 'WPA2')) {
        return "WPA2";
    } else if ((beacontype == 'WPAand11i') || (beacontype == 'WPA/WPA2')) {
        return "WPA/WPA2";
    } else {
        return beacontype;
    }
}

function formatSeconds(value) {
    var secondTime = parseInt(value);
    var minuteTime = 0;
    var hourTime = 0;
    if (secondTime > 60) {
        minuteTime = parseInt(secondTime / 60);
        secondTime = parseInt(secondTime % 60);
        if(minuteTime > 60) {
            hourTime = parseInt(minuteTime / 60);
            minuteTime = parseInt(minuteTime % 60);
        }
    }
    var result = "" + parseInt(secondTime) + "s";

    if (minuteTime > 0) {
        result = "" + parseInt(minuteTime) + "mins" + result;
    }
    if (hourTime > 0) {
        result = "" + parseInt(hourTime) + "hours" + result;
    }
    return result;
}


var wifi2tableArr = new Array();
wifi2tableArr.push([GetLanguage("status001"), GetWifiStatus(wifi2G.SSIDStatus), ""]);
wifi2tableArr.push(["SSID", wifi2G.SSID, ""]);
wifi2tableArr.push([GetLanguage("status012"), wifi2G.BSSID, ""]);
wifi2tableArr.push([GetLanguage("status021"), GetBeaconType(wifi2G.BeaconType), ""]);
wifi2tableArr.push([GetLanguage("status022"), WlanChannel2g, ""]);

var wifi7for2GtableArr = new Array();
if (wifi7for2G.domain) {
  wifi7for2GtableArr.push([GetLanguage("status001"), GetWifiStatus(wifi7for2G.SSIDStatus), ""]);
  wifi7for2GtableArr.push(["SSID", wifi7for2G.SSID, ""]);
  wifi7for2GtableArr.push([GetLanguage("status012"), wifi7for2G.BSSID, ""]);
  wifi7for2GtableArr.push([GetLanguage("status021"), GetBeaconType(wifi7for2G.BeaconType), ""]);
  wifi7for2GtableArr.push([GetLanguage("status022"), WlanChannel2g, ""]);
}

var wifi5tableArr = new Array();
wifi5tableArr.push([GetLanguage("status001"), GetWifiStatus(wifi5G.SSIDStatus), ""]);
wifi5tableArr.push(["SSID", wifi5G.SSID, ""]);
wifi5tableArr.push([GetLanguage("status012"), wifi5G.BSSID, ""]);
wifi5tableArr.push([GetLanguage("status021"), GetBeaconType(wifi5G.BeaconType), ""]);
wifi5tableArr.push([GetLanguage("status022"), WlanChannel5g, ""]);

var wifi7for5GtableArr = new Array();
if (wifi7for5G.domain) {
  wifi7for5GtableArr.push([GetLanguage("status001"), GetWifiStatus(wifi7for5G.SSIDStatus), ""]);
  wifi7for5GtableArr.push(["SSID", wifi7for5G.SSID, ""]);
  wifi7for5GtableArr.push([GetLanguage("status012"), wifi7for5G.BSSID, ""]);
  wifi7for5GtableArr.push([GetLanguage("status021"), GetBeaconType(wifi7for5G.BeaconType), ""]);
  wifi7for5GtableArr.push([GetLanguage("status022"), WlanChannel5g, ""]);
}

var systemtableArr = new Array();
systemtableArr.push([GetLanguage("status031"), deviceInfos[0].Description, ""]);
systemtableArr.push([GetLanguage("status032"), formatSeconds(deviceInfos[0].UpTime), ""]);
systemtableArr.push([GetLanguage("status024"), deviceInfos[0].SerialNumber, ""]);
systemtableArr.push([GetLanguage("status025"), deviceInfos[0].SoftwareVersion, ""]);
systemtableArr.push([GetLanguage("status026"), deviceInfos[0].HardwareVersion, ""]);
systemtableArr.push([GetLanguage("status027"), cpuUsed, ""]);
systemtableArr.push([GetLanguage("status028"), memUsed, ""]);
systemtableArr.push([GetLanguage("status029"), systemdsttime, ""]);

var tableStyleArr = [45, 40, 15];

function getStatus(val) {
    if (language.toUpperCase() == "PORTUGUESE") {
        return val == "1" ? "Ativo" : "Off";
    } else {
        return val == "1" ? "On" : "Off";
    }
}
</script>
</head>
<body id="wanbody">
<div id="content">
<script>
    CreatHeaderTitle(GetLanguage("status001"), GetLanguage("status002"));

    if (typeWord != "BR") {
        CreatStatusInfoTable(GetLanguage("status003"), "waninfotable", wantableArr, tableStyleArr);
    }

    CreatStatusInfoTable(GetLanguage("status004"), "laninfotable", lantableArr, tableStyleArr);

    if (typeWord != "BR") {
      CreatStatusInfoTable("Wi-Fi 2.4GHz", "wlaninfotable", wifi2tableArr, tableStyleArr);
      if (wifi7for2G.domain) {
        CreatStatusInfoTable("Wi-Fi 7 2.4GHz", "wlaninfotable72G", wifi7for2GtableArr, tableStyleArr);
      }
      CreatStatusInfoTable("Wi-Fi 5GHz", "wlaninfotable5g", wifi5tableArr, tableStyleArr);
      if (wifi7for5G.domain) {
        CreatStatusInfoTable("Wi-Fi 7 5GHz", "wlaninfotable75g", wifi7for5GtableArr, tableStyleArr);
      }
    }

    CreatStatusInfoTable(GetLanguage("status005"), "laninfotable", systemtableArr, tableStyleArr);
</script>
</div>

</body>
</html>
