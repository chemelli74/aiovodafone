<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1"/>
<link rel="stylesheet" type="text/css" href="/Cuscss/frame.css?03fa5651e1972f63229090335" />
<link rel="stylesheet" type="text/css" href="/Cuscss/overview.css?03fa5651e1972f63229090335" />
<script language="javascript" src="/resource/common/jquery.min.js?03fa5651e1972f63229090335"></script>
<script language="javascript" src="/resource/common/util.js?03fa5651e1972f63229090335"></script>
<script language="JavaScript" src="/Cusjs/ptvdfjs.js?03fa5651e1972f63229090335"></script>
<script language="JavaScript" src="/frameaspdes/portuguese/ssmpdes.js?03fa5651e1972f63229090335"></script>
<script language="javascript" src="/html/amp/common/wlan_list.asp"></script>
<script language="JavaScript" src="../../../Cusjs/ptvdfjs.js?03fa5651e1972f63229090335"></script>
<script language="JavaScript" type="text/javascript">

var curUserType = '1';
var CfgMode = 'PTVDF2WIFI_PWD';
var UserDevices = new Array();
var para = '';
var devtype = '';
var menulist = [];
var activeMenuId = null;
var wifiDev = new Array();
var wifiDevOnline = new Array();
var wifiDevOffline = new Array();
var guestwifiDevOnline = new Array();
var guestwifiDevOffline = new Array();
var wifiDevNumOnline = 0;
var wifiDevNumOffline = 0;
var guestwifiDevNumOnline = 0;
var guestwifiDevNumOffline = 0;
var wlanStaBoostCount2g = 0;
var wlanStaBoostCount5g = 0;
var boostAddId;
var editNetWorkDomain;
var editNetWorkNum;
var selectImgIndex;
var GroupNameFirst;
var ethNumOnline = 0;
var imgInfo = ["../images/game.png", "../images/landline-phone.png", "../images/laptop.png", "../images/playstation.png", "../images/printer.png",
               "../images/smartphone.png", "../images/tablet.png", "../images/tv.png", "../images/tv-center-center-2000.png", "../images/vox.png"]
var activeImgInfo = ["../images/game_active.png", "../images/landline-phone_active.png", "../images/laptop_active.png", "../images/playstation_active.png", "../images/printer_active.png",
               "../images/smartphone_active.png", "../images/tablet_active.png", "../images/tv_active.png", "../images/tv-center-center-2000_active.png", "../images/vox_active.png"]
function stDftPrinter(domain, PrinterEnable, PrinterName) {
    this.domain = domain;
    this.PrinterEnable = PrinterEnable;
    this.PrinterName = PrinterName;
}
var dftPrinters = new Array(new stDftPrinter("InternetGatewayDevice.Services.X_HW_Printer","0",""),null);
var dftPrinter = dftPrinters[0];
var SMBEnable = '0';

var WlanInfo = new Array();
WlanInfo = new Array(new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1","1","ath0","TestSSID"),new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e2","0","ath1","TestSSID\x2dGuest"),new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e3","0","ath2","TestSSID\x5fWiFi7"),new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e4","0","ath6","TestSSID\x5fWiFi7"),new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e5","1","ath4","TestSSID"),new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e6","0","ath5","TestSSID\x2dGuest"),null);
var AttachConfs = new Array(new stAttachConf("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1\x2eX\x5fHW\x5fAttachConf","0"),new stAttachConf("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e2\x2eX\x5fHW\x5fAttachConf","0"),new stAttachConf("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e3\x2eX\x5fHW\x5fAttachConf","0"),new stAttachConf("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e4\x2eX\x5fHW\x5fAttachConf","0"),new stAttachConf("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e5\x2eX\x5fHW\x5fAttachConf","0"),new stAttachConf("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e6\x2eX\x5fHW\x5fAttachConf","0"),null); 
var wlanStaBoostList = new Array(null);

var productName = 'HG8247B7\x2d8N'.toUpperCase();

var UserDhcpInfo;
var UserDevInfo;

var token="0303030303030303030303030303030303030303030303030303030303030303"
$.ajax({
    type : "POST",
    async : false,
    cache : false,
    url : "userDevSendArp.cgi?RequestFile=overview.asp",
    data: 'x.X_HW_Token=' + token,
    success : function(data) {
    }
});

function GetOldLanUserDevInfo(func) {
    $.ajax({
        type : "POST",
        async : false,
        cache : false,
        url : "/html/bbsp/common/getLanUserDevInfo_ptvdf.asp",
        success : function(data) {
            UserDevInfo = dealDataWithFun(data);
            if (func) {
                func(UserDevInfo);
            }
        }
    });
}

function GetLanUserDevInfo(func) {
    setTimeout(function() {
        GetOldLanUserDevInfo(func);
    }, 1000);
}

function stWlan(domain,enable,name,ssid) {
    this.domain = domain;
    this.enable = enable;
    this.name = name;
    this.ssid = ssid;
}
function USERDeviceInfo(Domain,IpAddr,MacAddr,PortID,DevType,DevStatus,PortType,HostName,DeviceType,UserDevAlias,LeaseTimeRemaining,GroupName,Time) {
    this.Domain 	= Domain;
    this.IpAddr	    = (IpAddr.length == 0)?"--":IpAddr;
    this.MacAddr	= MacAddr;
    this.PortID = PortID; 
    this.DevType	= DevType;
    this.DevStatus 	= DevStatus;
    this.PortType	= PortType;
    this.HostName	= HostName;
    this.DeviceType = DeviceType;
    this.UserDevAlias = UserDevAlias;
    this.LeaseTimeRemaining = LeaseTimeRemaining;
    if(GroupName=="") {
        this.GroupName = "0;0";
    }else{
        this.GroupName = GroupName;
    }
    this.Time	= Time;
}
var g_AllUserDevinfo = new Array(new USERDeviceInfo("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.1","192\x2e168\x2e1\x2e11","02\x3a00\x3a00\x3a00\x3a00\x3a01","LAN1","\x2d\x2d","Online","ETH","","0","","0","","0\x3a14"),new USERDeviceInfo("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.2","192\x2e168\x2e1\x2e37","02\x3a00\x3a00\x3a00\x3a00\x3a02","SSID1","\x2d\x2d","Offline","WIFI","","0","","0","","28\x3a4"),new USERDeviceInfo("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.3","192\x2e168\x2e1\x2e1","02\x3a00\x3a00\x3a00\x3a00\x3a03","LAN1","\x2d\x2d","Online","ETH","","0","","0","","4\x3a52"),new USERDeviceInfo("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.4","192\x2e168\x2e1\x2e31","02\x3a00\x3a00\x3a00\x3a00\x3a04","LAN1","\x2d\x2d","Offline","ETH","","0","","0","","0\x3a6"),new USERDeviceInfo("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.5","0\x2e0\x2e0\x2e0","02\x3a00\x3a00\x3a00\x3a00\x3a05","SSID1","","Offline","WIFI","","0","","0","","29\x3a14"),new USERDeviceInfo("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.6","192\x2e168\x2e1\x2e84","02\x3a00\x3a00\x3a00\x3a00\x3a06","LAN1","\x2d\x2d","Offline","ETH","","0","","0","","0\x3a6"),null);
var allUserDevinfo = truncate(g_AllUserDevinfo)
var onLineDev = [];
for (let index = 0; index < allUserDevinfo.length; index++) {
    if(allUserDevinfo[index].DevStatus.toUpperCase() == "ONLINE" && allUserDevinfo[index].PortType.toUpperCase() == "ETH") {
        onLineDev.push(allUserDevinfo[index]);
    }
}
function stPhysicalMedium(domain, Name, Status, X_HW_SafeRemove) {
    this.domain = domain;
    this.Name = Name;
    this.Status = Status;
    this.X_HW_SafeRemove = X_HW_SafeRemove;
}
var usblist = new Array(null)
function stWlanStaBoost(domain, ChipIndex, MACAddress, Duration, DurationTime) {
    this.domain = domain;
    this.ChipIndex = ChipIndex;
    this.MACAddress = MACAddress.toUpperCase();
    this.Duration = Duration;
    this.DurationTime = DurationTime;
    this.StaOnlineStu = 0;
}

function stAttachConf(domain,X_HW_AirtimeFairness) {
    this.domain = domain;
    this.X_HW_AirtimeFairness = X_HW_AirtimeFairness;
}

var AttachConf2g = new stAttachConf('0', '0');
var AttachConf5g = new stAttachConf('0', '0');
var wlanStaBoostMap = new Array();

for (i=0; i < WlanInfo.length-1; i++) {
    if (getWlanPortNumber(WlanInfo[i].name) >= SsidPerBand) {    
        AttachConf5g = AttachConfs[i];
    }

    if (getWlanPortNumber(WlanInfo[i].name) < SsidPerBand) {
        AttachConf2g = AttachConfs[i];
    }
}

for (var i=0; i < wlanStaBoostList.length-1; i++) {
    wlanStaBoostMap[wlanStaBoostList[i].MACAddress.toUpperCase()] = wlanStaBoostList[i];
    if (wlanStaBoostList[i].ChipIndex == 0) {
        wlanStaBoostCount2g++;
    } else if (wlanStaBoostList[i].ChipIndex == 1) {
        wlanStaBoostCount5g++;
    }

    if (wlanStaBoostList[i].Duration != 0) {
        wlanStaBoostList[i].StaOnlineStu = wlanStaBoostList[i].Duration * 3600 - wlanStaBoostList[i].DurationTime;
    }
}

function SetStaBoostTime() {
    var isUptime = 0;
    for (var i = 0; i < wlanStaBoostList.length-1; i++) {
        if (wlanStaBoostList[i].Duration != 0) {
            wlanStaBoostList[i].StaOnlineStu = wlanStaBoostList[i].StaOnlineStu - 1;
        }
        if (wlanStaBoostList[i].StaOnlineStu > 0) {
            isUptime = isUptime + 1;
        }
    }

    if (isUptime == 0) {
        clearInterval(showStaBoostTime);
        return;
    }
}

function checkAddStaBoost(freq) {
    var AttachConf = AttachConf2g;
    if (freq == "5G") {
        AttachConf = AttachConf5g;
    }

    if (AttachConf.X_HW_AirtimeFairness != 1) {
        alertVDF(framewifiinfo["framewifi002"]);
        return false;
    }

    if (((wlanStaBoostCount5g >= 2) && (freq == "5G")) || ((wlanStaBoostCount2g >= 2) && (freq == "2G"))) {
        alertVDF(framewifiinfo["framewifi003"]);
        return false;
    }

    return true;
}

function USERDevice(Domain,IpAddr,MacAddr,Port,IpType,DevType,DevStatus,PortType,Time,HostName,GroupName) {
    this.Domain     = Domain;
    this.IpAddr     = IpAddr;
    this.MacAddr    = MacAddr;
    this.Port       = Port;
    this.PortType   = PortType;
    this.DevStatus  = DevStatus;
    this.IpType     = IpType;
    if (IpType=="Static"){
        this.DevType="--";
    } else {
        if(DevType=="") {
            this.DevType    = "--"; 
        } else {
            this.DevType    = DevType;      
        }   
    }
    this.Time = Time;
    
    if (HostName=="") {
        this.HostName   = "--";
    } else {
       this.HostName    = HostName;
    }
    if(GroupName==""){
        this.GroupName = "0;0";
    }else{
        this.GroupName = GroupName;
    }
}

if (window.location.href.indexOf("type") != -1) {
    para = window.location.href.split("type")[1]; 
    devtype = para.split("=")[1];
}

var associatedDevice = new Array(new stAssociatedDevice("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1\x2eAssociatedDevice\x2e1","02\x3a00\x3a00\x3a00\x3a00\x3a07","\x2d73"),new stAssociatedDevice("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1\x2eAssociatedDevice\x2e2","02\x3a00\x3a00\x3a00\x3a00\x3a08","\x2d55"),new stAssociatedDevice("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1\x2eAssociatedDevice\x2e3","02\x3a00\x3a00\x3a00\x3a00\x3a09","\x2d46"),new stAssociatedDevice("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1\x2eAssociatedDevice\x2e4","02\x3a00\x3a00\x3a00\x3a00\x3a05","\x2d34"),new stAssociatedDevice("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e5\x2eAssociatedDevice\x2e1","02\x3a00\x3a00\x3a00\x3a00\x3a0a","\x2d84"),new stAssociatedDevice("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e5\x2eAssociatedDevice\x2e2","02\x3a00\x3a00\x3a00\x3a00\x3a0b","\x2d80"),new stAssociatedDevice("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e5\x2eAssociatedDevice\x2e3","02\x3a00\x3a00\x3a00\x3a00\x3a0c","\x2d68"),new stAssociatedDevice("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e5\x2eAssociatedDevice\x2e4","02\x3a00\x3a00\x3a00\x3a00\x3a0d","\x2d72"),null);

function stAssociatedDevice(domain, AssociatedDeviceMACAddress, X_HW_RSSI) {
    this.domain = domain;
    this.AssociatedDeviceMACAddress = AssociatedDeviceMACAddress;
    this.X_HW_RSSI = X_HW_RSSI;
}

var showStaBoostTime;
$(document).ready( function() {
    var $submenu = $('.submenu');
    var $mainmenu = $('.container');
    $submenu.hide();

    $(".container .li2").on('click', function() {
        if ($(this).find('.icon2').hasClass('rotate')) {
            $(this).find('.icon2').removeClass("rotate");
            $(this).find('.icon2').addClass("rotate1");
        } else {
            $(this).find('.icon2').removeClass("rotate1");
            $(this).find('.icon2').addClass("rotate");
        }
        $(this).next('.submenu').slideToggle().siblings('.submenu').slideUp();
    });
    showStaBoostTime = setInterval("SetStaBoostTime()",1000);
});
var newLastList = [];
var onLineDevList = [];
GetLanUserDevInfo(function(para) {
    UserDevices = para;

    let offLineDevList = [];
    for (let k = 0; k < allUserDevinfo.length; k++) {
        if (allUserDevinfo[k].GroupName == '0;0') {
            allUserDevinfo[k].GroupName = '7;7'
            if (allUserDevinfo[k].PortType.toUpperCase() == "WIFI") {
                allUserDevinfo[k].GroupName = '7;5'
            }
        }
        if (allUserDevinfo[k].PortType.toUpperCase() == "ETH") {
            if (allUserDevinfo[k].DevStatus.toUpperCase() == "ONLINE") {
                onLineDevList.push(allUserDevinfo[k]);
            } else {
                offLineDevList.push(allUserDevinfo[k]);
            }
        }
    }
    var allUserDevList = onLineDevList.concat(offLineDevList);

    if (allUserDevList.length <= 3) {
        GetDevInfo(allUserDevList);
    } else {
        var newFirstList = allUserDevList.slice(0,3);
        newLastList =  allUserDevList.slice(3)
        GetDevInfo(newFirstList);
        showMoreNetDev();
        
    } 

    GetWifiDevInfo();
    if ('LINEDEV' == devtype.toUpperCase()) {
        ShowCntDevDetails(devtype, EthDev);
    }
});

function RedirectToPhone() {
    window.parent.onFirstMenuChange("PhoneID", "CallLogID");
}

function RedirectToPhoneSche() {
    window.parent.onFirstMenuChange("PhoneID", "RingingScheduleID");
}

function RedirectToVoiceState() {
    window.parent.onFirstMenuChange("StatusSupportId", "StatusId");
    window.parent.onThirdMenuChange("VoiceStatusID");
}

function RedirectToWifiSche() {
    window.parent.onFirstMenuChange("Wi-FiID", "PowerSavingModeID");
}

function RedirectToWifiGeneral() {
    window.parent.onFirstMenuChange("Wi-FiID", "GeneralID");
}

function RedirectToWifiWps() {
    window.parent.onFirstMenuChange("Wi-FiID", "WPSID");
}
function RedirectToNetwork() {
    window.parent.onFirstMenuChange("SettingsID", "LANIPv4ID");
}

function RedirectToUSB() {
    window.parent.onFirstMenuChange("SettingsID","USBID");
}

function intoPrint() {
    window.parent.onFirstMenuChange("SettingsID","PrinterSharingID");
}
function USERDeviceV6(Domain,IP,Scope,HostName,DevType,MacAddr,DevStatus,PortType,PortID) {
    this.Domain     = Domain;
    this.IP         = IP;
    this.Scope      = Scope;
    this.HostName       = HostName;
    this.DevType        = DevType;
    this.MacAddr        = MacAddr;
    this.DevStatus      = DevStatus;
    this.PortType       = PortType;
    this.PortID     = PortID;
}
var UserDevIpv6Info = new Array(new USERDeviceV6("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.5.IPv6Address.1","fe80\x3a\x3ae56b\x3a3e94\x3a737b\x3a46df","LLA","","\x2d\x2d","02\x3a00\x3a00\x3a00\x3a00\x3a05","Online","WIFI","SSID1"),null);
function UserDevFindIpv6(domain) {
    var ipaddr_gua = "";

    var usrdevid = domain.split(".")[4];

    for(var i = 0; i < UserDevIpv6Info.length - 1; i++)
    {
        var usrdev6id = UserDevIpv6Info[i].Domain.split(".")[4];

        if((usrdevid == usrdev6id)&&(UserDevIpv6Info[i].Scope == "GUA") && (UserDevIpv6Info[i].DevStatus.toUpperCase() == "ONLINE"))
        {
            ipaddr_gua = UserDevIpv6Info[i].IP;
            break;
        }
    }
    return ipaddr_gua;
}

function GetConnectTime(userDev) {
    let LanTime = userDev.Time.split(":")
    let day = 0;
    let hour = LanTime[0];
    if (LanTime[0] >= 24) {
        day = parseInt(LanTime[0]/24);
        hour = LanTime[0]%24;
    }

    let min = LanTime[1];
    var connecttime = " " + day + "d " + hour + "h " + min + "mins";
    if (userDev.DevStatus.toUpperCase() != "ONLINE") {
        connecttime = "--";
    }

    return connecttime;
}

function GetDevInfo(allUserDevList) {

    for (let j = 0; j < allUserDevList.length; j++) {
        allUserDevList[j].arryIndex = j
    }

    ethNumOnline = allUserDevList.length;

    for(var i = 0; i < allUserDevList.length; i++) {
        var devName;
        if (allUserDevList[i].UserDevAlias == "") {
            devName = allUserDevList[i].HostName;
        } else {
            devName = allUserDevList[i].UserDevAlias;
        }
        if (devName == "") {
            devName = "--";
        }
        GroupNameFirst = allUserDevList[i].GroupName.split(";")[0];
        var port = allUserDevList[i].PortID.replace("LAN","");

        var unit_h = (parseInt(allUserDevList[i].Time.split(":")[0],10) > 1) ? " hours" : " hour";
        var unit_m = (parseInt(allUserDevList[i].Time.split(":")[1],10) > 1) ? " minutes" : " minute";

        document.getElementById("network").innerHTML += '<li class="li2" id="networkLi_'+ i + '">'
        + '<img src="'+ imgInfo[allUserDevList[i].GroupName.split(";")[1]] + '" class="icon">'
        + '<span title=" ' + escapeHTML(devName) + ' ">' + escapeHTML(restrictingLength(devName,10))  + '</span>'
        + '<i><img src="../images/arrow-down.png" class="icon2" id = "iconTop" ></i>'
        + '<i><img src="../images/arrow-up.png" class="icon2 " id ="iconBottm" style ="display:none"></i>'
        + '</li>'
        + '<ul class="submenu" style="display:none;">'
        + '<li><i><img src="../images/button-info-desktop.png" onClick="showEthDetailInfo(this.id, false)" id="' +allUserDevList[i].Domain + "-"+ allUserDevList[i].arryIndex + '"></i></li>'
        + '<li><i><img src="../images/button-edit-desktop.png" onClick="showEditbox(this.id)" id="' + allUserDevList[i].Domain + "-"+ allUserDevList[i].GroupName.split(";")[1] + '"></i></li>'
        + '<div class="detailInfo" id="detailInfo_' + i +'">'
        + '<div id="trangle"></div>'
        + '<div class="infobox">' + framedesinfo["frame034"] + escapeHTML(devName) + '</div>'
        + '<div class="infobox">IPv4:' + allUserDevList[i].IpAddr + '</div>'
        + '<div class="infobox">IPv6:' + UserDevFindIpv6(allUserDevList[i].Domain) + '</div>'
        + '<div class="infobox">' + framedesinfo["frame033"] + allUserDevList[i].MacAddr.toUpperCase() + '</div>'
        + '<div class="infobox">'+ framedesinfo["frame035"] + GetConnectTime(allUserDevList[i]) + '</div>'
        + '<div class="infobox">LAN:' + port + '</div>'
        + '</div>'
        + '</ul>'
            $('#network .li2').on('click',function(){
            if ($(this).next('.submenu').is(':hidden')) {

                 $(this).find('#iconTop')[0].style.display = 'none';
                 $(this).find('#iconBottm')[0].style.display = 'block';




            } else {
                $(this).find('#iconTop')[0].style.display = 'block';
                $(this).find('#iconBottm')[0].style.display = 'none';
            }
            $(this).next('.submenu').slideToggle();
            })
        if (allUserDevList[i].DevStatus == "Offline") {
            $("#networkLi_" + i).addClass("op40");
            $("#networkLi_" + i).find('#iconTop')[0].style.display = 'none';
            $("#networkLi_" + i).find('#iconBottm')[0].style.display = 'none';
        }
    }       
}

function showMoreNetDev() {
    var titileHtml = framewifiinfo["framewifi005"] + newLastList.length +  framewifiinfo["framewifi006"] 
    var html = '<ul id="showNetWork" class="container" onClick="showNetWork(this,event);">' +
        '<li class="li2" style="padding:0 0 0 15px;">' +
        '<span id = "shoeMoreSpan">' +
        '<span style="display: inline;" id="shoeMore" title = "'+ titileHtml +'" >' + restrictingLength(titileHtml,20) + '</span>' +
        '</span>' +
        '<span style="display:none;" id="hideMoreSpan" title = "'+ framewifiinfo["framewifi007"] +'">' + restrictingLength(framewifiinfo["framewifi007"],20) + '</span>' +
        '<i><img src="../images/arrow-down.png" id = "downPic" class="icon2" ></i>' +
        '<i><img src="../images/arrow-up.png" id = "upPic" class="icon2" style = "display:none"></i>' +
        '</li>' +
        '</ul>';
    $("#network").append(html);
    var moreHtml = '<div id = "moreHtml" class = "container" style = "display: none"></div>'
    $("#network").append(moreHtml);
    for (var i = 0; i < newLastList.length; i++) {
        var devName = '';
        if (newLastList[i].UserDevAlias == "") {
            devName = newLastList[i].HostName;
        } else {
            devName = newLastList[i].UserDevAlias;
        }
        if (devName == "") {
            devName = "--";
        }
        let childHtml = '<li margin-left: 16px; class="li2"  id="networkMore_'+ i + '">'
        + '<img src="'+ imgInfo[newLastList[i].GroupName.split(";")[1]] + '" class="icon">'
        + '<span>' + escapeHTML(restrictingLength(devName, 10)) + '</span>'
        + '<i><img src="../images/arrow-down.png" class="icon2" id = "iconTop" ></i>'
        + '<i><img src="../images/arrow-up.png" class="icon2 " id ="iconBottm" style ="display:none"></i>'
        + '</li>'
        + '<ul class="submenu" style="display:none;">'
        + '<li><i><img src="../images/button-info-desktop.png" onClick="showEthDetailInfo(this.id, true)" id="' + newLastList[i].Domain + "-"+ i + '"></i></li>'
        + '<li><i><img src="../images/button-edit-desktop.png" onClick="showEditbox(this.id)" id="' + newLastList[i].Domain + "-"+ newLastList[i].GroupName.split(";")[1] + '"></i></li>'
        + '<div class="detailInfo" id="moreDetailInfo_' + i +'">'
        + '<div id="trangle"></div>'
        + '<div class="infobox">' + framedesinfo["frame034"] + escapeHTML(devName) + '</div>'
        + '<div class="infobox">IPv4:' + newLastList[i].IpAddr + '</div>'
        + '<div class="infobox">IPv6:' + UserDevFindIpv6(newLastList[i].Domain) + '</div>'
        + '<div class="infobox">' + framedesinfo["frame033"] + newLastList[i].MacAddr.toUpperCase() + '</div>'
        + '<div class="infobox">'+ framedesinfo["frame035"] + GetConnectTime(newLastList[i]) + '</div>'
        + '<div class="infobox">LAN:' + newLastList[i].PortID.replace("LAN","") + '</div>'
        + '</div>'
        + '</ul>'
        $("#moreHtml").append(childHtml);
        if (newLastList[i].DevStatus == "Offline") {
            $("#networkMore_" + i).addClass("op40");
            $("#networkMore_" + i).find('#iconTop')[0].style.display = 'none';
            $("#networkMore_" + i).find('#iconBottm')[0].style.display = 'none';
        }
    }

    $('#moreHtml .li2').on('click',function() {
        if ($(this).next('.submenu').is(':hidden')) {
            $(this).find('#iconTop')[0].style.display = 'none';
            $(this).find('#iconBottm')[0].style.display = 'block';
        } else {
            $(this).find('#iconTop')[0].style.display = 'block';
            $(this).find('#iconBottm')[0].style.display = 'none';
        }

        $(this).next('.submenu').slideToggle();
    })
}

function showNetWork(obj,event) {
    if ($("#moreHtml")[0].style.display == 'block') {
        $("#downPic")[0].style.display = 'block'
        $("#upPic")[0].style.display = 'none';
        setDisplay("moreHtml",0);
        setDisplay("hideMoreSpan",0);
        setDisplay("shoeMoreSpan",1);
    } else {
        setDisplay("moreHtml",1);
        $("#downPic")[0].style.display = 'none'
        $("#upPic")[0].style.display = 'block';
        setDisplay("hideMoreSpan",1);
        setDisplay("shoeMoreSpan",0);
    }
}


var isUpFlag = true;
function ShowNetworkDevice(id) {
    if (isUpFlag) {
        $("#showDevNum").css("display","none")
        $("#hideDevNum").css("display","block")
        isUpFlag = false;
    } else {
        $("#showDevNum").css("display","block")
        $("#hideDevNum").css("display","none")
        isUpFlag = true;
    }
}

function InitWifiDevOnline(wifiDev, i, isGuest) {
    var time = wifiDev.Time.split(":");
    var day = 0;
    var hour = time[0];
    var min = time[1];
    if (time[0] >= 24) {
        day = parseInt(time[0]/24);
        hour = time[0]%24;
    }
    var connecttime = " " + day + "d " + hour + "h " + min + "mins";
    if (wifiDev.Time == "") {
        connecttime = "--";
    }
    var Port = wifiDev.Port;
    var freq = "2.4GHz";
    if (Port == "SSID1" || Port == "SSID2") {
        freq = "2.4GHz";
    } else if (['SSID3', 'SSID5', 'SSID6'].indexOf(Port) !== -1) {
        freq = "5GHz";
    }
    
    var Rssi = GetAssociateInfoByMac(wifiDev.MacAddr);
    var signalRssi = (Rssi == 0) ? 0 : Rssi.X_HW_RSSI;
    if (signalRssi < -80) {
        var imgSrc = "signal_empty.png";
    } else if ((signalRssi >= -80 ) && (signalRssi <= -75)) {
        var imgSrc = "signal_1from4.png";
    } else if ((signalRssi > -75 )&&(signalRssi <= -69 )) {
        var imgSrc = "signal_2from4.png";
    } else if ((signalRssi > -69 )&&(signalRssi <= -63 )) {
        var imgSrc = "signal_3from4.png";
    } else if (signalRssi > -63 ) {
        var imgSrc = "signal_full.png";
    }

    var allUserDevive = new Array();
    for(var k = 0; k < allUserDevinfo.length; k++) {
        if (wifiDev.MacAddr.toUpperCase() == allUserDevinfo[k].MacAddr.toUpperCase()) {
            allUserDevive = allUserDevinfo[k];
        }
    }

    var showName = (wifiDev.UserDevAlias == "") ? wifiDev.HostName : wifiDev.UserDevAlias;

    var html = '<li class="li2" id="' + isGuest + 'wifiLi_'+ i + '" onClick="ShowWifiPic(this);">'
    + '<div><img src="' + imgInfo[allUserDevive.GroupName.split(";")[1]] + '" class="icon"></div>'
    + '<div class="wifiStaName" title="' + escapeHTML(showName) + '">' + escapeHTML(restrictingLength(showName, 11)) + '</div>'
    + '<div><img id="' + isGuest + 'wifiSignal_'+ i + '" src="../images/' + imgSrc + '" class="strengthIcon"></div>'
    + '<div id="' + isGuest + 'wifiBoost_'+ i + '" style="display:none;"><img src="../images/boost_error_icon.png" class="strengthIcon"></div>'
    + '<i><img src="../images/arrow-down.png" class="icon2"></i>'
    + '</li>'
    + '<ul id="' + isGuest + 'clickShow_' + i + '" class="submenu" style="display:none;">'
    + '<li><i><img src="../images/button-info-desktop.png" onClick="showWifiDetailInfo(this.id)" id="detail' + isGuest + 'img_'+ i + '"></i></li>'
    + '<li><i><img src="../images/button-edit-desktop.png" onClick="showEditbox(this.id)" id="' + allUserDevive.Domain + "-" + allUserDevive.GroupName.split(";")[1] + '"></i></li>'
    + '<li><i><img src="../images/boosting_wifi.png" onClick="showWifiBoost(this.id)" id="' + isGuest + 'boostimg_'+ i + '">'
    +'<img style="display:none;" src="../images/boost_error_icon.png" onClick="DelWifiBoost(this.id)" id="' + isGuest + 'Delboostimg_'+ i + '"></i></li>'
    + '<div id="' + isGuest + 'boostTime_'+ i + '" style="margin-left:80px;display:none;"></div>'
    + '<div class="detailInfo" style="padding-left: 20px;" id="' + isGuest + 'wifidetailInfo_' + i +'">'
    + '<div id="trangle"></div>'
    + '<div class="infobox">Name:' + escapeHTML(showName) + ' (' + freq + ')' + '</div>'
    + '<div class="infobox">IPv4:' + wifiDev.IpAddr + '</div>'
    + '<div class="infobox">IPv6:' + UserDevFindIpv6(wifiDev.Domain) + '</div>'
    + '<div class="infobox">MAC Address:<span id="' + isGuest + 'OnlineMac'+ i + '">' + wifiDev.MacAddr.toUpperCase() + '</span></div>'
    + '<div class="infobox">Connection duration:' + connecttime + '</div>'
    + '</div>'
    + '</ul>'
    $("#" + isGuest + "wifiContent").append(html);
    if (i >= 3 && (isGuest == "")) {
        document.getElementById("wifiLi_" + i).style.display="none";
        $("clickShow_"+ i).addClass("wifihide");
    } else if (isGuest == "guest") {
        document.getElementById(isGuest + "wifiLi_" + i).style.display="none";
    }
    
    if (CheckMacInBoost(wifiDev.MacAddr)) {
        document.getElementById(isGuest + "wifiBoost_" + i).style.display="";
    }
}

function InitWifiDevOffline(wifiDev, i, isGuest) {
    var allUserDevive = new Array();
    for(var k = 0; k < allUserDevinfo.length; k++) {
        if (wifiDev.MacAddr.toUpperCase() == allUserDevinfo[k].MacAddr.toUpperCase()) {
            allUserDevive = allUserDevinfo[k];
        }
    }

    var showName = (wifiDev.UserDevAlias == "") ? wifiDev.HostName : wifiDev.UserDevAlias;
    var html = '<li class="li2 op40" id="' + isGuest + 'wifiLi_'+ i + '" title="' + escapeHTML(showName) + '">'
            + '<img src="' + imgInfo[allUserDevive.GroupName.split(";")[1]] + '" class="icon">'
            + '<span>' + escapeHTML(restrictingLength(showName, 11)) + '</span>'
            + '</li>'
            $("#" + isGuest + "wifiContent").append(html);

    if (i >= 3 && (isGuest == "")) {
        document.getElementById("wifiLi_" + i).style.display="none";
    } else if (isGuest == "guest") {
        document.getElementById(isGuest + "wifiLi_" + i).style.display="none";
    }
}

function ShowMoreDevice(id,num) {
    var html = '<ul id="ShowwifiDeviceUl" class="container" title="' + framewifiinfo["framewifi005"] + num + framewifiinfo["framewifi006"] + '" onClick="ShowwifiDevice(this.id);">' +
        '<li class="li2" style="padding:0 0 0 15px;overflow: hidden;text-overflow: ellipsis;white-space: nowrap;padding-right:20px;">' +
        '<span style="display: inline;margin-left: -3px;" id="showDeviceSpan">' + framewifiinfo["framewifi005"] + '</span>' +
        '<span style="display: inline;" id="hideWifiNumSpan">' + num + '</span>' +
        '<span style="display: inline;" id="showDeviceSpanLast">' + framewifiinfo["framewifi006"] + '</span>' +
        '<span style="display:none;" id="hideDeviceSpan">' + framewifiinfo["framewifi007"] + '</span>' +
        '<i><img src="../images/arrow-down.png" class="icon2"></i>' +
        '</li>' +
        '</ul>';
    $("#" + id).append(html);
}

function ChangeTitleById(id) {
    var text = document.getElementById(id).innerText;
    document.getElementById(id).title = text;
}

function ShowwifiDevice(id) {
    var isGuest = (id.indexOf("guest") != -1) ? "guest" : "";
    var deviceNum = (isGuest == "guest") ? (guestwifiDevNumOnline + guestwifiDevNumOffline) : (wifiDevNumOnline + wifiDevNumOffline);
    var value = document.getElementById(isGuest + "hideDeviceSpan").style.display;
    var isHide = "";

    if (value == "none") {
        document.getElementById(isGuest + "hideDeviceSpan").style.display = "inline";
        document.getElementById(isGuest + "showDeviceSpan").style.display = "none";
        document.getElementById(isGuest + "hideWifiNumSpan").style.display = "none";
        document.getElementById(isGuest + "showDeviceSpanLast").style.display = "none";
        isHide = "";
    } else {
        document.getElementById(isGuest + "hideDeviceSpan").style.display = "none";
        document.getElementById(isGuest + "showDeviceSpan").style.display = "inline";
        document.getElementById(isGuest + "hideWifiNumSpan").style.display = "inline";
        document.getElementById(isGuest + "showDeviceSpanLast").style.display = "inline";
        isHide = "none";
    }
    ChangeTitleById(isGuest + "ShowwifiDeviceUl");
    $(".wifihide").css("display", isHide);

    for (var i = 0;i < deviceNum; i++) {
        if (i >= 3 && isGuest == "") {
            document.getElementById("wifiLi_" + i).style.display = isHide;
        } else if (isGuest == "guest") {
            document.getElementById(isGuest + "wifiLi_" + i).style.display = isHide;
        }
    }

    if (isGuest == "") {
        if ($('#ShowwifiDeviceUl .icon2').hasClass('rotate')) {
            $('#ShowwifiDeviceUl .icon2').removeClass("rotate");
            $('#ShowwifiDeviceUl .icon2').addClass("rotate1");
        } else {
            $('#ShowwifiDeviceUl .icon2').removeClass("rotate1");
            $('#ShowwifiDeviceUl .icon2').addClass("rotate");
        }
    }
}

function GetWifiDevInfo() {
    wifiDevNum = 0;
    for (var i=0; UserDevices.length > 0 && i < UserDevices.length-1; i++) {
        if (UserDevices[i].PortType.toUpperCase() == "WIFI") {
            wifiDev[wifiDevNum] = new USERDevice("","","","","","","","","","");
            wifiDev[wifiDevNum] = UserDevices[i];
            if (['SSID1', 'SSID3', 'SSID4', 'SSID5'].indexOf(UserDevices[i].Port) != -1) {
                if (UserDevices[i].DevStatus.toUpperCase() == "ONLINE") {
                    wifiDevOnline[wifiDevNumOnline] = new USERDevice("","","","","","","","","","");
                    wifiDevOnline[wifiDevNumOnline] = UserDevices[i];
                    wifiDevNumOnline++;
                    wifiDevNum++;
                } else {
                    wifiDevOffline[wifiDevNumOffline] = new USERDevice("","","","","","","","","","");
                    wifiDevOffline[wifiDevNumOffline] = UserDevices[i];
                    wifiDevNumOffline++;
                }
            } else if (UserDevices[i].Port == "SSID2" || UserDevices[i].Port == "SSID6") {
                if (UserDevices[i].DevStatus.toUpperCase() == "ONLINE") {
                    guestwifiDevOnline[guestwifiDevNumOnline] = new USERDevice("","","","","","","","","","");
                    guestwifiDevOnline[guestwifiDevNumOnline] = UserDevices[i];
                    guestwifiDevNumOnline++;
                    wifiDevNum++;
                } else {
                    guestwifiDevOffline[guestwifiDevNumOffline] = new USERDevice("","","","","","","","","","");
                    guestwifiDevOffline[guestwifiDevNumOffline] = UserDevices[i];
                    guestwifiDevNumOffline++;
                }
            }
        }
    }
    document.getElementById("WIFInum").innerHTML = wifiDevNum;
    
    for (var j = 0;j < (wifiDevNumOnline + wifiDevNumOffline);j++) {
        if (j == 3) {
            var showDevice = wifiDevNumOnline + wifiDevNumOffline - 3;
            ShowMoreDevice("wifiContent", showDevice);
        }

        if (j < wifiDevNumOnline) {
            InitWifiDevOnline(wifiDevOnline[j], j, "");
        } else {
            var temp = j - wifiDevNumOnline;
            InitWifiDevOffline(wifiDevOffline[temp],j, "");
        }
    }
    for (var i = 0; i < guestwifiDevNumOnline; i++) {
        InitWifiDevOnline(guestwifiDevOnline[i], i, "guest");
    }

    for (var i = 0; i < guestwifiDevNumOffline; i++) {
        var temp = i + guestwifiDevNumOnline;
        InitWifiDevOffline(guestwifiDevOffline[i], temp, "guest");
    }
    
    var guestWifiNum = guestwifiDevNumOnline + guestwifiDevNumOffline;
    document.getElementById("guesthideWifiNumSpan").innerHTML = guestWifiNum;
    document.getElementById("guestShowwifiDeviceUl").title = framewifiinfo["framewifi005"] + guestWifiNum + framewifiinfo["framewifi006"];
}

var showStaBoostRelease = new Array;
var showStaBoostReleaseId = new Array;
var showStaBoostReleaseTime = new Array;
function ShowWifiPic(ele) {
    var id = ele.id.split("_")[1];
    var isGuest = (ele.id.indexOf("guest") != -1) ? "guest" : "";
    if ($('#' + isGuest + 'wifiLi_' + id + ' .icon2').hasClass('rotate')) {
        $('#' + isGuest + 'wifiLi_' + id + ' .icon2').removeClass("rotate");
        $('#' + isGuest + 'wifiLi_' + id + ' .icon2').addClass("rotate1");
    } else {
        $('#' + isGuest + 'wifiLi_' + id + ' .icon2').removeClass("rotate1");
        $('#' + isGuest + 'wifiLi_' + id + ' .icon2').addClass("rotate");
    }
    var mac = document.getElementById(isGuest + 'OnlineMac'+ id).innerHTML;
    $('#' + isGuest + 'clickShow_' + id).slideToggle().siblings('#clickShow_' + id + ' .submenu').slideUp(); 
    if (CheckMacInBoost(mac)) {
        $('#' + isGuest + 'wifiBoost_'+ id).slideToggle().siblings('#clickShow_' + id + ' .submenu').slideDown();
        $('#' + isGuest + 'Delboostimg_' + id).slideToggle().siblings('#clickShow_' + id + ' .submenu').slideUp(); 
        $('#' + isGuest + 'boostimg_'+ id).slideToggle().siblings('#clickShow_' + id + ' .submenu').slideDown();
        var staBoostInfo = GetBoostInfoByMac(mac);
        if (staBoostInfo.Duration != 0) {
            clearInterval(showStaBoostRelease[id]);
            setDisplay(isGuest + 'boostTime_'+ id, 1);
            showStaBoostReleaseId[id] = isGuest + 'boostTime_'+ id;
            showStaBoostReleaseTime[id] = staBoostInfo.StaOnlineStu;
            showStaBoostRelease[id] = setInterval(function(){ 
                document.getElementById(showStaBoostReleaseId[id]).innerHTML = TimeChange(showStaBoostReleaseTime[id]);
                if (showStaBoostReleaseTime[id] == 0) {
                    clearInterval(showStaBoostRelease[id]);
                    return;
                }
                showStaBoostReleaseTime[id] = showStaBoostReleaseTime[id] - 1;
            }, 1000)
        } else {
            setDisplay(isGuest + 'boostTime_'+ id, 0);
        }
    } else {
        setDisplay(isGuest + 'boostTime_'+ id, 0);
    }
}

function TimeFormatChange(time) {
    if (time < 10) {
        return "0" + time;
    }

    return time;
}

function TimeChange(time) {
    var hour = parseInt(time / 3600);
    var min = parseInt((time%3600) / 60);
    var second = parseInt((time%3600)%60);
    
    return TimeFormatChange(hour) + ":" + TimeFormatChange(min) + ":" + TimeFormatChange(second);
}

function InitAlertContent() {
    var html = "";
    window.parent.document.getElementById("wifiContent").innerHTML = "";
    html += '<p class="title">' +
            '<span class="language-string">' + framewifiinfo["framewifi010"] + '</span>' +
            '</p>' + 
            '<div class="row">' + 
            '<div class="wifileft" style="float:left;padding-left: 15px;">' +
            '<input id="boost2" class="radio-checked" name="allow" value="2" type="radio">' +
            '<label for="boost2" style="margin-right:5px"></label>' +
            '<span class="language-string">2 ' + framewifiinfo["framewifi011"] + '</span>' +
            '</div>' +
            '<div class="wifileft" style="float:left;padding-left: 15px;">' +
            '<input id="boost4" class="radio-checked" name="allow" value="4" type="radio">' +
            '<label for="boost4" style="margin-right:5px"></label>' +
            '<span class="language-string">4 ' + framewifiinfo["framewifi011"] + '</span>' +
            '</div>' +
            '<div class="wifileft" style="float:left;padding-left: 15px;">' +
            '<input id="boost8" class="radio-checked" name="allow" value="8" type="radio">' +
            '<label for="boost8" style="margin-right:5px"></label>' +
            '<span class="language-string">8 ' + framewifiinfo["framewifi011"] + '</span>' +
            '</div>' +
            '<div class="wifileft" style="float:left;padding-left: 15px;">' +
            '<input id="boost0" class="radio-checked" name="allow" checked="checked" value="0" type="radio">' +
            '<label for="boost0" style="margin-right:5px"></label>' +
            '<span class="language-string">' + framewifiinfo["framewifi012"] + '</span>' +
            '</div></div>' +
            '<div class="apply-cancel">' +
            '<input id="continueButton" class="button button-apply add" type="button" value="' + framewifiinfo["framewifi013"] + '" onClick="SaveBoostTime();">' +
            '<input id="cancelButton" class="button button-cancel " type="button" value="' + framewifiinfo["framewifi014"] + '" onClick="hideWifiBlock();">' +
            '</div>';
    window.parent.document.getElementById("wifiContent").innerHTML = html;
}

function showWifiBoost(val) {
    boostAddId = val;
    window.parent.getElementById("wifiBackground").style.display = "";
    window.parent.getElementById("wifiContent").style.display = "";
    InitAlertContent();
}

function GetBoostInfoByMac(mac) {
    for (var i=0; i < wlanStaBoostList.length - 1; i++) {
        if (wlanStaBoostList[i].MACAddress == mac.toUpperCase()) {
            return wlanStaBoostList[i];
        }
    }
}

function CheckMacInBoost(mac) {
    for (var i=0; i < wlanStaBoostList.length - 1; i++) {
        if (wlanStaBoostList[i].MACAddress == mac.toUpperCase()) {
            return true;
        }
    }
    return false;
}

function GetAssociateInfoByMac(macAddr) {
    for (var key in associatedDevice) {
        if (associatedDevice[key] == null) {
            continue;
        }
        if (associatedDevice[key].AssociatedDeviceMACAddress.toUpperCase() == macAddr.toUpperCase()) {
            return associatedDevice[key];
        }
    }

    return 0;
}

function GetFreqByMac(macAddr) {
    for (var key in associatedDevice) {
        if (associatedDevice[key] == null) {
            continue;
        }
        if (associatedDevice[key].AssociatedDeviceMACAddress.toUpperCase() == macAddr.toUpperCase()) {
            var instID = getWlanInstFromDomain(associatedDevice[key].domain);
            if (instID >= ssidStart2G && instID <= ssidEnd2G) {
                return "2G";
            } else if (instID >= ssidStart5G && instID <= ssidEnd5G) {
                return "5G";
            }
        }
    }
}

function SaveBoostTime() {
    window.parent.hideWifiBlock();
    var index = boostAddId.split("_")[1];
    var staInfo = (boostAddId.indexOf("guest") != -1) ? guestwifiDevOnline : wifiDevOnline;
    var boostTime = window.parent.getRadioValue("allow");
    var macAddr = staInfo[index].MacAddr.toUpperCase();
    var freq = GetFreqByMac(macAddr);
    if (checkAddStaBoost(freq) == false) {
        return;
    }

    var Form = new webSubmitForm();
    Form.addParameter('x.MACAddress', macAddr);
    Form.addParameter('x.Duration', boostTime);
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));

    var addDomain = 'InternetGatewayDevice.LANDevice.1.WiFi.Radio.1.X_HW_WLANSTABoost';
    if (freq == "5G") {
        addDomain = 'InternetGatewayDevice.LANDevice.1.WiFi.Radio.2.X_HW_WLANSTABoost';
    }

    Form.setAction('add.cgi?x='+ addDomain +'&RequestFile=overview.asp');
    Form.submit();
}

function DelWifiBoost(val) {
    var index = val.split("_")[1];
    var staInfo = (val.indexOf("guest") != -1) ? guestwifiDevOnline : wifiDevOnline;
    var macAddr = staInfo[index].MacAddr.toUpperCase();
    var DelStaBoostDomain = wlanStaBoostMap[macAddr].domain;
    var Form = new webSubmitForm();
    Form.addParameter(DelStaBoostDomain, '');
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.setAction('del.cgi?x='+ 'InternetGatewayDevice.LANDevice.1.WiFi.Radio.{i}.X_HW_WLANSTABoost' +'&RequestFile=overview.asp');
    Form.submit();
}

function hideAllWifiDetailInfo(isGuest) {
    if (isGuest === 'guest') {
        for (let i = 0; i < guestwifiDevNumOnline; i++) {
            $("#" + isGuest + "wifidetailInfo_" + i).hide();
        }

        return;
    }

    for (let i = 0; i < wifiDevNumOnline; i++) {
        $("#" + isGuest + "wifidetailInfo_" + i).hide();
    }
}

function showWifiDetailInfo(val) {
    var index = val.split("_")[1];
    var isGuest = (val.indexOf("guest") != -1) ? "guest" : "";
    $("#" + isGuest + "wifidetailInfo_" + index).css({"position":"absolute","left":"-45px"});
    if ($("#" + isGuest + "wifidetailInfo_" + index).is(':hidden')) {
            hideAllWifiDetailInfo(isGuest);
            $("#" + isGuest + "wifidetailInfo_" + index).show();
    } else {
            $("#" + isGuest + "wifidetailInfo_" + index).hide();
    }
}

function hideAllEthDetailInfo() {
    for (let i = 0; i < ethNumOnline; i++) {
        $("#detailInfo_" + i).hide();
    }

    for (let j = 0; j < newLastList.length; j++) {
        $('#moreDetailInfo_' + j).hide();
    }
}

function showEthDetailInfo(val, isMoreDev) {
    var index = val.split("-")[1];
    var prefix = isMoreDev ? "#moreDetailInfo_" : "#detailInfo_";
    $(prefix + index).css({"position":"absolute","left":"-45px"});
    if ($(prefix + index).is(':hidden')) {
            hideAllEthDetailInfo();
            $(prefix + index).show();
    } else {
            $(prefix + index).hide();
    }
}

function showEditbox(id) {
    $("#box").fadeIn();
    for (let i = 0; i < allUserDevinfo.length; i++) {
        if (allUserDevinfo[i].Domain == id.split("-")[0]) {
            if (allUserDevinfo[i].UserDevAlias == "") {
                $("#devNameSet").val(allUserDevinfo[i].HostName)
                $("#devNameSet").attr("value",allUserDevinfo[i].HostName);
            } else {
                $("#devNameSet").val(allUserDevinfo[i].UserDevAlias)
                $("#devNameSet").attr("value",allUserDevinfo[i].UserDevAlias);

            }
        }
    }
    var docheight = $(document).height();
    $("body").append("<div id='greybackground'></div>");
    $("#greybackground").css({"opacity":"0.5","height":docheight,"position":"absolute","left":"0","top":"0","background":"#000","width":"100%","height":"100%","z-index":"5"});
    editNetWorkDomain = id.split("-")[0];
    editNetWorkNum = id.split("-")[1]
    $("#img_" + editNetWorkNum).attr("src", activeImgInfo[editNetWorkNum]);
　　 return false;
}
</script>
<script language="JavaScript" type="text/javascript">
var vagIndex = 0;
var vagLastInst = '0';
var upMode = '1';
var opticInfo = '\x2d18\x2e07';
var ethLinkStatus = new Array(new ethLinkMode("InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.1.CommonConfig","1"),new ethLinkMode("InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.2.CommonConfig","0"),new ethLinkMode("InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.3.CommonConfig","0"),new ethLinkMode("InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.4.CommonConfig","0"),null);

function ethLinkMode(domain, Link) {
    this.domain	= domain;
    this.Link = Link;
}

function stProfile(Domain, Enable)
{
    this.Domain = Domain;
    this.Enable = Enable;
}

var AllProfile = new Array(new stProfile("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1","Enabled"),null);
vagIndex = GetVagIndexByInst(vagLastInst);

function GetVagIndexByInst(vagInst)
{
    for (var i = 0; i < AllProfile.length-1; i++) {
        if (AllProfile[i].profileid == vagInst) {
            return i;
        }
    }

    return 0;
}

function stRingSchedule(Domain, Enable, Policy)
{
    this.Domain = Domain;
    this.Enable = Enable;
    this.Policy = Policy;
}

var scheduleStatus = new Array(new stRingSchedule("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.X_HW_RingSchedule","0","0"),null);

function stLine(Domain, DirectoryNumber, PhyReferenceList, X_HW_Description)
{
    this.Domain = Domain;
    this.DirectoryNumber = DirectoryNumber;
    this.PhyReferenceList = PhyReferenceList;
    this.X_HW_Description = X_HW_Description;
}

function stLineURI(Domain, URI)
{
    this.Domain = Domain;
    this.URI = URI;
}

var AllLineURI = new Array(new stLineURI("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1.SIP","\x2b15555550100"),new stLineURI("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.2.SIP","line2"),null);
var LineURI = new Array();
for (var i = 0; i < AllLineURI.length-1; i++) {
    LineURI[i] = AllLineURI[i];
}

var AllLine = new Array(new stLine("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1","\x2b15555550100","1",""),new stLine("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.2","line2","2",""),null);
var LineList = new Array(new Array(),new Array(),new Array(),new Array());

for (var i = 0; i < AllLine.length-1; i++) {
    var temp = AllLine[i].Domain.split('.');
     var Vagindex = GetVagIndexByInst(temp[5]);
    LineList[Vagindex].push(AllLine[i]);
}

function stAuth(Domain, AuthUserName)
{
    this.Domain = Domain;
    this.AuthUserName = AuthUserName;

    var temp = Domain.split('.');
    this.key = '.' + temp[7] + '.';
}

var AllAuth = new Array(new stAuth("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1.SIP","\x2b15555550100\x40ims\x2evodafone\x2ept"),new stAuth("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.2.SIP","line2"),null);
var Auth = new Array();
for (var i = 0; i < AllAuth.length-1; i++) {
    Auth[i] = AllAuth[i];
}

    var User = new Array();
function stUser(Domain, UserId)
{
    this.Domain = Domain;
    this.UserId = UserId;
}

for (var i = 0; i < AllLine.length - 1; i++) {
    User[i] = new stUser();
    User[i].UserId = AllLine[i].DirectoryNumber;
}

var vdfPhoneNumber = new Array();
function  GetPhoneNumber(inputstring)
{
    if (inputstring.indexOf(":") >= 0) {
        var URIpart = inputstring.split(':');
        var k1 = URIpart[1];
        var k2 = k1.split('@');
        var k3 = k2[0];
        if (k3 == "") {
            number = "--";
        } else {
            number = k3;
        }
    } else {
        var URIpart = inputstring.split('@');
        var k = URIpart[0];
        if (k == "") {
            number = "--";
        } else {
            number = k;
        }
    }
    return number;
}

for (i = 0; i < AllLine.length - 1; i++) {
    if (AllLineURI[i].URI != "") {
        vdfPhoneNumber[i] = GetPhoneNumber(LineURI[i].URI);
    } else if (AllLine[i].DirectoryNumber != "") {
        vdfPhoneNumber[i] = GetPhoneNumber(User[i].UserId);
    } else if (AllAuth[i].AuthUserName != "") {
        vdfPhoneNumber[i] = GetPhoneNumber(Auth[i].AuthUserName);
    } else {
        vdfPhoneNumber[i] = "--";
    }
}

var htmlDescriptionId = new Array();
for (i = 0; i < AllLine.length - 1; i++) {
    htmlDescriptionId[i] = "Description" + i;
}

function setVagInfo()
{
    if (AllProfile[0] == null) {
        return;
    }
    for (i = 0; i < AllLine.length - 1; i++) {
         setText(htmlDescriptionId[i], AllLine[i].X_HW_Description);
    }
}

function AddSubmitParam(Form,type)
{
    var domain = "";
    var add = "";
    var des = "";
    if (AllProfile[0] == null) {
        return false;
    }

    domain ='x=' + AllProfile[vagIndex].Domain;
    for (i = 0; i < AllLine.length - 1; i++) {
        add = 'Add' + i;
        var des = add +'.X_HW_Description';
        Form.addParameter(des, getValue(htmlDescriptionId[i]));
        domain += '&' + add +'=' + LineList[vagIndex][i].Domain;
    }
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));

    Form.setAction('set.cgi?' + domain + '&RequestFile=html/voip/vdfphonenumber/sipphonenumvdf.asp');
    setDisable('SaveApply_button',1);   
    setDisable('Cancel_button',1);      
}

function vdfvspaisValidStrlen(cfgName, val, len)
{
    if (val.length > len) {
        AlertEx(cfgName + vdfsipline['vspa_cantexceed']  + len  + vdfsipline['vspa_characters']);
        return false;
    }
}

function CheckForm(type)
{
    var ulret=0;
    var i = AllLine.length - 1;
    for (i = 0; i < AllLine.length - 1; i++) {
        ulret |= CheckForm1(i); 
    }
    if (ulret != true) {
        return false;
    }

    return true;
}

function CheckForm1(index)
{
    if ('' != removeSpaceTrim(getValue(htmlDescriptionId[index]))) {
        if (vdfvspaisValidStrlen(vdfsipline['vspa_linedes'],getValue(htmlDescriptionId[index]),32) == false) {
            return false;
        }
    }
    return true;
}

function ButtonCancel()
{
    LoadFrame();
}


function LoadFrame()
{
    setVagInfo();
    if (AllLine.length - 1 >= 1) {
        setDisplay('PhoneNumApplyCancel', 1);
    }
}
var htmlInfo = "";
for (let i = 0; i < imgInfo.length; i++) {
    htmlInfo += '<div class="icon">'
        htmlInfo += '<img src="'+ imgInfo[i] + '" id="img_'+ i + '" onclick="changeImage(this.id)">'
    htmlInfo += '</div>'
}
function changeImage(id) {
    selectImgIndex = id.split("_")[1];
    $("#img_" + editNetWorkNum).attr("src", imgInfo[editNetWorkNum]);
    $("#img_" + selectImgIndex).attr("src", activeImgInfo[selectImgIndex]);
    editNetWorkNum = selectImgIndex
}
function SaveApply() {
    var Form = new webSubmitForm();
    Form.addParameter('x.UserDevAlias',document.getElementById('devNameSet').value);
    Form.addParameter('x.GroupName',GroupNameFirst+";"+editNetWorkNum);
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.setAction('set.cgi?' + 'x=' + editNetWorkDomain + '&RequestFile=overview.asp');                                
    Form.submit();	
}
function RedirectiveToUSB() {
    window.parent.onFirstMenuChange("SettingsID", "ContentSharingID");
    window.parent.onThirdMenuChange("SambaID");
}

function ShowNoConnection()
{
    document.getElementById("accessstatetxt").innerHTML = framedesinfo["frame045"];
    document.getElementById("accessstate").style.background = "red";
    document.getElementById("accessstateline").style.zIndex = -1;
    document.getElementById("accessstateimg").src = "../images/red_line_long.png";
}

function SetAccessStatus(opticState)
{
    if (upMode == 3 || upMode == 11) {
        if (ethLinkStatus[ethLinkStatus.length - 2].Link == 1) {
            document.getElementById("accessstatetxt").innerHTML = framedesinfo["frame044"];
        } else {
            ShowNoConnection();
        }
    } else {
        if (opticState == false) {
            ShowNoConnection();
        }
    }
}

function LoadOpticFrame()
{
    var isOpticalOk = true;

    if(opticInfo == "--" || opticInfo == "") {
        isOpticalOk = false;
    }
    SetAccessStatus(isOpticalOk);
    setOntImage();
}

function setOntImage() {
    let image = 'ont-l3-wide-pt.png';
    if (productName === 'HN8255X6S-8X') {
        image = 'HN8255X6s-8X.jpg';
        $(".ontleft").css("width", '36%');
    }
    image = '../images/' + image;
    $("#ontImg").attr("src", image);
}
</script>
<style>
.wifihide{
    
}
.strengthIcon {
    width: 18px;
    height: auto;
    float: left;
    display: block;
    margin-top: 15px;
    margin-left: 4px;
}
</style>


</head>
<body class="mainpagebody" onload="LoadOpticFrame();" style="position: relative;">
<div id="mainpage">
    <div id="ontimgpart">
       <div class="ontleft">
            <div id="accessstate" class="overview-image-top-left" style="right:142px;">
                <span id="accessstatetxt"><script>document.write(framedesinfo["frame043"]);</script></span>
                <div id="accessstateline" class="line" style="z-index:-1;right:-150px;">
                    <img id="accessstateimg" src="../images/green_line_long.png" />
                </div>
            </div>
       </div>
       <div class="ontright">
            <img id="ontImg" />
       </div>
    </div>
    <div id="onlineconnectpart">
        <div id="onlineTop"></div>
        <div id="onlineBottom">
            <ul class="onlineBottomul">
                <script>
                    let usbOnline = [];
                    var printerCount = 0;
                    for (var i = 0; i < usblist.length - 1; i++) {
                        if (usblist[i].Status.toUpperCase() == "ONLINE") {
                            usbOnline.push(usblist[i]);
                        }
                    }
                    if (dftPrinter.PrinterName != "") {
                        printerCount = 1;
                    }
                    var usbDevCount = usbOnline.length + printerCount;
                    document.write('<li style="width:20%;box-sizing: border-box;padding-left: 41px;cursor: pointer;font-family:VodafoneRgRegular;" id="WIFInum" onclick="RedirectToWifiGeneral()">0</li>');
                    document.write('<li style="width:30%;font-family:VodafoneRgRegular;text-align: center;">' + onLineDev.length + '</li>');
                    document.write('<li style="width:30%;text-align: center;font-family:VodafoneRgRegular;">' + usbOnline.length + '</li>');
                    document.write('<li class="voipAlline" Onclick="RedirectToPhone();" style="width:20%;padding-right: 41px;text-align: right;cursor: pointer;font-family:VodafoneRgRegular;">' + htmlencode(AllLine.length - 1) + '</li>');
                </script>
               
            </ul>
        </div>
    </div>
    <div id="contentpart">
        <div class="coulmn1">
            <div id="itemTitle">
                <a href="#" onClick="RedirectToWifiGeneral()">
                    <img src="../images/wifi.png" class="icon">
                    <span>Wi-Fi</span>
                </a>
            </div>
            <ul class="container">
                <li class="li1" onClick="RedirectToWifiSche()">
                    <a href="#">
                        <img src="../images/schedule.png" class="icon">
                        <span>
                            <script>
                                var wlanScheEnable = '0';
                                if (wlanScheEnable == 1) {
                                    document.write(framewifiinfo["framewifi001"]);
                                } else {
                                    document.write(framewifiinfo["framewifi008"]);
                                }
                            </script>
                        </span>
                    </a>
                </li>
                <li class="li1" onClick="RedirectToWifiWps()">
                    <a href="#">
                        <img src="../images/wps.png" class="icon">
                        <span>
                            <script>
                                var wlanWpsEnable2g = '0';
                                var wlanWpsEnable5g = '0';
                                if (wlanWpsEnable2g == 1 || wlanWpsEnable5g == 1) {
                                    document.write(framewifiinfo["framewifi004"]);
                                } else {
                                    document.write(framewifiinfo["framewifi009"]);
                                }
                            </script>
                        </span>
                    </a>
                </li>
            </ul>
            <ul class="container" id="wifiContent">
            </ul>
        </div>
        <div class="coulmn1">
            <div id="itemTitle">
                <a onClick='RedirectToNetwork();'>
                    <img src="../images/network.png" class="icon">
                    <script>
                        document.write('<span>'+ framedesinfo["frame041"] + '</span>');
                    </script>
                </a>
            </div>
            <ul class="container" id="network">
            </ul>
            
        </div>
        <div class="coulmn1">
            <div id="itemTitle">
                <a onClick="RedirectToUSB();">
                    <img style="width: 23px;" src="../images/usb.png" class="icon">
                    <span>USB</span>
                </a>
            </div>
            <ul class="container" id="usb">
                <script>
                var sharingEnable = "";
                if (SMBEnable == 1) {
                    sharingEnable = framedesinfo['frame031'];
                } else {
                    sharingEnable = framedesinfo['frame032'];
                }
                var printerName = (dftPrinter.PrinterName != "") ? dftPrinter.PrinterName : "--";
                    document.write('<li class="li1">');
                    document.write('<a href="#">');
                    document.write('<img src="../images/schedule.png" class="icon">');
                    document.write('<span onClick="RedirectiveToUSB()">'+ framedesinfo['frame030'] + sharingEnable + '</span>');
                    document.write('</a></li>');
                if (dftPrinter.PrinterEnable == 1) {
                    document.write('<li class="li2" onclick = "intoPrint()">');
                    document.write('<img src="../images/printer.png" class="icon">');
                    document.write('<span>'+ printerName + '</span>');
                    document.write('</li>');
                }
                    var usbHtml = "";
                    for (var i = 0; i < usblist.length - 1; i++) {
                        if (usblist[i].Status.toUpperCase() == "ONLINE") {
                            usbHtml += '<li class="li2">';
                        } else {
                            usbHtml += '<li class="li2 op40">';
                        }
                        usbHtml += '<img src="../images/hard-drive.png" class="icon">';
                        usbHtml += '<span>'+ htmlencode(usblist[i].Name) + '</span>';
                        usbHtml += '</li>';
                    }
                    $("#usb").append(usbHtml);
                </script>
            </ul>
        </div>
        <div class="coulmn1">
            <div id="itemTitle">
                <a onClick='RedirectToPhone();'>
                    <img style="width: 20px;" src="../images/phone.png" class="icon">
                    <script>
                        document.write('<span>'+ framephoneinfo["framephone001"] + '</span>');
                    </script>
                </a>
            </div>
            <ul class="container">
                <li class="li1">
                    <a href="#">
                        <img src="../images/schedule.png" class="icon">
                        <script language="JavaScript" type="text/javascript">
                            if (scheduleStatus[0].Enable == 1) {
                                document.write('<span onClick="RedirectToPhoneSche()">' + framephoneinfo["framephone002"] + '</span>');
                            } else {
                                document.write('<span onClick="RedirectToPhoneSche()">' + framephoneinfo["framephone003"] + '</span>');
                            }
                        </script>
                    </a>
                </li>
                    <script language="JavaScript" type="text/javascript">
                        if (AllLine.length - 1 == 0) {
                            document.write('<li class="li2"><span> </span></li>');
                        }
                        for (i = 0; i < AllLine.length - 1; i++) {
                            document.write('<li class="li2"><img src="../images/landline-phone.png" class="icon">')
                            document.write('<span onClick="RedirectToVoiceState();">' + htmlencode(vdfPhoneNumber[i]) + '</span></li>');
                        }
                    </script>
                
            </ul>
        </div>
        <div style="clear:both;padding-top:10px;">
            <div class="coulmn1">
                <div id="itemTitle">
                    <a href="#" onClick="RedirectToWifiGeneral()">
                        <img src="../images/wifi.png" class="icon">
                        <span> Guest Wi-Fi</span>
                    </a>
                </div>
                <ul id="guestShowwifiDeviceUl" class="container" onClick="ShowwifiDevice(this.id);">
                    <li class="li2" style="padding:0 0 0 15px;overflow: hidden;text-overflow: ellipsis;white-space: nowrap;padding-right:20px;">
                        <span style="display: inline;margin-left:-3px;" id="guestshowDeviceSpan"><script>document.write(framewifiinfo["framewifi005"]);</script></span>
                        <span style="display: inline;" id="guesthideWifiNumSpan"></span>
                        <span style="display: inline;" id="guestshowDeviceSpanLast"><script>document.write(framewifiinfo["framewifi006"]);</script></span>
                        <span style="display:none;" id="guesthideDeviceSpan"><script>document.write(framewifiinfo["framewifi007"]);</script></span>
                        <i><img src="../images/arrow-down.png" class="icon2"></i>
                    </li>
                </ul>
                <ul class="container wifihide" id="guestwifiContent">
                </ul>
            </div>
        </div>
    </div>

        <div id="box">
            <script>
                document.write('<p class="title">' + framedesinfo["frame036"] + '</p>');
            </script>
            <div class="icon-row">
                <script>
                    document.write('<p class="language-string">' + framedesinfo["frame037"] + '</p>');
                </script>
                <div class="icon-wrapper" id = "editIcon">
                    <div class="icon">
                        <img src="../images/game.png">
                    </div>
                </div>
            </div>
            <div class="name-row">
                <script>
                    document.write('<p class="language-string">' + framedesinfo["frame034"] + '</p>');
                </script>
                <input type="text" value="" class="name-input" id= "devNameSet">
            </div>
            <div class="apply-cancel">
                <script>
                    document.write('<input class="button button-apply" value="' + framedesinfo["frame038"] + '" title="Save" type="button" onClick="SaveApply()">');
                    document.write('<input class="button button-cancel" value="' + framedesinfo["frame039"] + '" title="Cancel" type="button" id="closeBtn">');
                </script>
            </div>
        </div>
    <script>
    $(function(){
　　var screenwidth;
    var screenheight;
    var mytop;
    var getPosLeft;
    var getPosTop
　　screenwidth = $(window).width();
　　screenheight = $(window).height();
　　mytop = $(document).scrollTop();
　　getPosLeft = screenwidth/2 - 260;
　　getPosTop = screenheight/2 - 150;
　　//$("#box").css({"left":getPosLeft,"top":getPosTop});
　　$(window).resize(function(){
　　  screenwidth = $(window).width();
　　  screenheight = $(window).height();
　　  mytop = $(document).scrollTop();
　　  getPosLeft = screenwidth/2 - 260;
　　  getPosTop = screenheight/2 - 150;
　　  //$("#box").css({"left":getPosLeft,"top":getPosTop+mytop});
　　});
 
　　$(window).scroll(function(){
　　  screenwidth = $(window).width();
　　  screenheight = $(window).height();
　　  mytop = $(document).scrollTop();
　　  getPosLeft = screenwidth/2 - 260;
　　  getPosTop = screenheight/2 - 150;
　　});
 
　　$("#closeBtn").click(function() {
　　  $("#box").hide();
      $("#img_" + editNetWorkNum).attr("src", imgInfo[editNetWorkNum]);
　　  $("#greybackground").remove();
　　  return false;
　　});
});
$("#editIcon").html(htmlInfo)
$("#img_" + editNetWorkNum).attr("src", activeImgInfo[editNetWorkNum]);
for (let i = 0; i < allUserDevinfo.length; i++) {
        if (allUserDevinfo[i].Domain == editNetWorkDomain) {
            if (allUserDevinfo[i].HostName == "") {
                $("#devNameSet").val(allUserDevinfo[i].UserDevAlias)
                $("#devNameSet").attr("value",allUserDevinfo[i].UserDevAlias);
            } else {
                $("#devNameSet").val(allUserDevinfo[i].HostName)
                $("#devNameSet").attr("value",allUserDevinfo[i].HostName);
            }
        }
    }
if (curUserType == 2) {
    $('a').css('pointer-events', 'none');
    $('li').css('pointer-events', 'none');
}
    </script>
</div>
<input type="hidden" name="onttoken" id="hwonttoken" value="0404040404040404040404040404040404040404040404040404040404040404">
<div style="height:10px;width:100%;"></div>
</body>
</html>
