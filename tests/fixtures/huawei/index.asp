<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" class=" js flexbox canvas canvastext webgl no-touch geolocation postmessage websqldatabase indexeddb hashchange history draganddrop websockets rgba hsla multiplebgs backgroundsize borderimage borderradius boxshadow textshadow opacity cssanimations csscolumns cssgradients cssreflections csstransforms csstransforms3d csstransitions fontface generatedcontent video audio localstorage sessionstorage webworkers applicationcache svg inlinesvg smil svgclippaths" style="background-color: #ebebeb;" lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<title></title>
<link rel="stylesheet" type="text/css" href="Cuscss/frame.css?03fa5651e1972f63229090335"/>      
<script src="../resource/common/jquery.min.js?03fa5651e1972f63229090335" type="text/javascript"></script>
<script src="../resource/common/util.js?03fa5651e1972f63229090335" type="text/javascript"></script>  
<script language="JavaScript" src="Cusjs/ptvdfjs.js?03fa5651e1972f63229090335"></script>
<script id="langResource" language="JavaScript" src="/frameaspdes/portuguese/ssmpdes.js?03fa5651e1972f63229090335"></script>  
<script language="javascript" src="/html/bbsp/common/wan_list_ptvdf.asp"></script>
<script language="javascript" src="/html/bbsp/common/wanipv6state.asp"></script>
<style>
#progress-bar-box {
    background-color: #f7f7f7;
    width: 316px;
    height: 30px;
    border: 1px solid #cccccc;
}

#progress-bar-image {
    background-color: #a8b400;
    width: 0px;
    height: 29px;
}
</style>
<script type="text/javascript">
window.wanCacheObj = { wanListCacheObj:{}, wanIpv6StateCacheObj:{}, wanOptType: 0, curWanState: '0', wanMonitorTimer: null };

function stDeviceInfo(domain, SoftwareVersion, UpTimeStr)
{
    this.domain = domain;
    this.SoftwareVersion = SoftwareVersion;
    this.UpTimeStr = UpTimeStr
}
var deviceInfos = new Array(new stDeviceInfo("InternetGatewayDevice.DeviceInfo","V5R024C00S114","1\x20day\x28s\x29\x2005\x3a14\x3a35"),null);
var SoftwareVersion = deviceInfos[0].SoftwareVersion;
var UpTimeStr = deviceInfos[0].UpTimeStr;

var UpgradeFlag = 0;
var upgradeStatusobj = {upgradeStatus:0};
var InstallNodeMenu = null;
var FirstMenuStr = "";
var SecondTmpMenuStr = "";
var g_ThirdMenuArry = [];
var SecondMenuArray = [];
var g_MenuList = [];
var g_AllListMenuForJump = [];
var activeMenuId = null;
var g_clickshow = false;
var curUserType = '1';
var loginNum = '1';
var sysUserType = '0';
var ModeType = 'Expert Mode';
var Var_DefaultLang = 'portuguese';
var Var_LastLoginLang = 'portuguese';
var Language ="";
var CfgMode = 'PTVDF2WIFI_PWD'.toUpperCase();
if(Var_LastLoginLang == '') {
    Language = Var_DefaultLang;
} else {
    Language = Var_LastLoginLang;
}


$.ajax({
    type : "POST",
    async : false,
    cache : false,
    url : "asp/getMenuArray.asp",
    success : function(data) {
         InstallNodeMenu  = dealDataWithFun(data);
    }
});

var UpgradeHeigthHandle = setInterval("setIframeHeight('functioncontent');", 200);
function GetIdByUrl(Type, BaseUrl) {
    var NewId = Type+"_";
    var MarkEnd="";
    try {
        var lastindex = BaseUrl.lastIndexOf('/');
        if (lastindex > -1) {
            NewId += BaseUrl.substring(lastindex+1, BaseUrl.length);
        } else {
            NewId += BaseUrl;
        }

        if (NewId.indexOf("?") > -1) {
            MarkEnd = NewId.split("?")[1];
        }
        NewId = NewId.split(".")[0]+MarkEnd;
    }catch(e){
        NewId += Math.round(Math.random() * 10000);
    }
    return NewId;
}

function GetMenuStr(datastr, length) {
    if (datastr.length > length) {
        var MenuName = GetStringContentForTitle(datastr, length);
        return MenuName;
    }
    return datastr;
}

var comfimParentId ="";
var comfimSpecialChildId ="";
var wlanParaSyncFlag = false;

function firstMenuSuceess() {
    doOk("confirmblackBackground");
    UpgradeFlag = 0;
    onFirstMenuEvent(comfimParentId,comfimSpecialChildId);
}

function onFirstMenuChange(ParentId,SpecialChildId) {
    showWifiPwdNote()
    if (UpgradeFlag == 1) {
        comfimParentId = ParentId;
        comfimSpecialChildId = SpecialChildId;
        confirmVDF(framedesinfo["frame040"],"firstMenuSuceess()");
        return
    } else {
        onFirstMenuEvent(ParentId,SpecialChildId);
    }
}

function onFirstMenuEvent(ParentId,SpecialChildId){
    var ClickId = (SpecialChildId == null || SpecialChildId == undefined) ? null : "Child" + SpecialChildId;

    $("#subnavigation_id").children().remove();
    $('#clearfixtest').find("li").children('a').removeClass('addFirstMenu');
    $('#' + ParentId).addClass('addFirstMenu');
    for (var FirstMenuIndex in InstallNodeMenu) {
        var id = InstallNodeMenu[FirstMenuIndex].id;
        var subMenus = InstallNodeMenu[FirstMenuIndex].subMenus;

        if (ParentId != id) {
            continue;
        }

        g_MenuList[id] = new stMenuData(id, '', 1,
                         InstallNodeMenu[FirstMenuIndex].deficon,
                         InstallNodeMenu[FirstMenuIndex].clickicon,
                         InstallNodeMenu[FirstMenuIndex].url, id);

        if (undefined != subMenus) {
            CreateSecondMenu(id, g_MenuList[id].path, subMenus,true);
            g_MenuList[id].hasChild = true;
        }
        
        break;
    }

    if (null == g_MenuList || false == g_MenuList[id].hasChild) {
        $("#content-reset-wrap").css("width","950px");
        $("#content-reset-wrap").css("margin-left","0px");
        FirstPageURL = InstallNodeMenu[FirstMenuIndex].url;
    } else {
        $("#content-reset-wrap").css("width","710px");
        $("#content-reset-wrap").css("margin-left","50px");

    }

    if("ChildonlyAppendArrayList" == ClickId) {
        return;
    }

    if (null != ClickId) {
        var subnavClickObj = null;
        var subnavDiv = document.getElementById('subnavigation_id');
        var LiObj = subnavDiv.getElementsByTagName('li');
        var subnavLilistLength = subnavDiv.getElementsByTagName('li').length;
        for (var i = 0;i < subnavLilistLength; i++){
            var subnavDivObj = LiObj[i]; 
            var subnavDivA = subnavDivObj.getElementsByTagName('a')[0];
            if (ClickId == LiObj[i].id) {
                subnavClickObj = subnavDivA; 
                break;
            }
        }

        if( (undefined != subnavClickObj) && (null != subnavClickObj) ) {
            subnavClickObj.click();
        }
    } else {
        if ('OverviewID' == ParentId) {
            $("#functioncontent").attr("src", FirstPageURL);
        } else {
            var subnavDiv = document.getElementById('subnavigation_id');
            var subnavDivA = subnavDiv.getElementsByTagName('a')[0];
            subnavDivA.click();
        }
    }
}
var comfimid = "";
var comfimSpecialChildId = "";

function secondMenuSuceess() {
    doOk("confirmblackBackground");
    UpgradeFlag = 0;
    onSecondMenuEvent(comfimid,comfimSpecialChildId);
}

function onSecondMenuChange(id,SpecialChildId) {
    if (UpgradeFlag == 1) {
        comfimid = id;
        comfimSpecialChildId = SpecialChildId;
        confirmVDF(framedesinfo["frame040"],"secondMenuSuceess()");
        return
    } else {
        onSecondMenuEvent(id,SpecialChildId);
    }
}

function onSecondMenuEvent(id,SpecialChildId) {
    var ClickId = (SpecialChildId == null || SpecialChildId == undefined) ? null : SpecialChildId;
    var SecondIndexId = "list_" + id;
    $("#menu-title").empty();
    $("#menu-usb").empty();
    $(".sub-navigation").children('li').find('a').removeClass("third_click");
    $("#" + id).addClass("third_click");
    $(".sub-navigation").children('li').find('ul').fadeOut('fast');
    $(".sub-navigation").children('li').find('a').addClass('second_click'); 
    $("#functioncontent").attr("src", SecondMenuArray[id].ThirdMenuUrl);
    
    if (null != ClickId) {
        $("#" + id).removeClass("second_click");
        $("#" + id).siblings('ul').find('li').children('a').addClass("second_click_children");
        $("#" + id).siblings('ul').fadeIn('fast');
        $("#menu-usb").append(g_ThirdMenuArry[id].ThirdMenuList);
        $("#menu-usb li:first a").addClass("active");
        $("#" + id).removeClass("third_click");
        var subnavClickObj = null;
        var subnavDiv = document.getElementById(SecondIndexId);
        var LiObj = subnavDiv.getElementsByTagName('li');
        var subnavLilistLength = subnavDiv.getElementsByTagName('li').length;
        for (var i = 0;i < subnavLilistLength; i++) {
            var subnavDivObj = LiObj[i]; 
            var subnavDivA = subnavDivObj.getElementsByTagName('a')[0];
            if(ClickId == subnavDivA.id){
                subnavClickObj = subnavDivA; 
                break;
            }
        }

        if( (undefined != subnavClickObj) && (null != subnavClickObj) ) {
            console.log(subnavClickObj);
            subnavClickObj.click();
        }
        return;
    }
    
    
    if (true == SecondMenuArray[id].hasChild) {
        $("#" + id).removeClass("second_click");
        $("#" + id).siblings('ul').find('li').children('a').addClass("second_click_children");
        $("#" + id).siblings('ul').fadeIn('fast');
        $("#menu-usb").append(g_ThirdMenuArry[id].ThirdMenuList);
        $("#menu-usb li:first a").addClass("active");
        
        if (SecondMenuArray[id].ThirdMenuUrl != "") {
            return;
        } else {
            $("#" + id).removeClass("third_click");
        }
        $("#" + id).siblings('ul').find('li').eq(0).children('a').addClass("third_click");
        var subnavDiv = document.getElementById('subnavigation_id');
        var subnavDivA = subnavDiv.getElementsByTagName('a')[0];
        var subnavDivUl = subnavDivA.nextSibling;
        if(null != subnavDivUl){
            var subnavDivUlA = subnavDivUl.getElementsByTagName('a')[0];
            subnavDivUlA.click();
        }
    }
}

function stSecondMenuTitle(id, secondtitle, ThirdMenuUrl, hasChild) {
    this.id             = id;
    this.secondtitle    = secondtitle;
    this.ThirdMenuUrl   = ThirdMenuUrl;
    this.hasChild       = hasChild;
}

function onThirdMenuChange(id,title) {
    $(".sub-navigation").children('li').find('a').removeClass("third_click");
    $(".thirdClass").children('li').find('a').removeClass("third_click");
    $("#" + id).addClass("third_click");
    $("#functioncontent").attr("src", g_MenuList[id].url);
}

function stMenuArrayList(id, MenuInfoList) {
    this.id             = id;
    this.MenuInfoList   = MenuInfoList;
}

function stThirdMenuList(id, ChildId, MenuInfoList) {
    this.id             = id;
    this.ChildId        = ChildId;
    this.MenuInfoList   = MenuInfoList;
}
var confirmlanguage = "";
function onChangeLanguage(language) {
    if (UpgradeFlag == 1) {
        confirmlanguage = language;
        confirmVDF(framedesinfo["frame040"],"languageSuceess()");
        return
    } else {
        changeLanguageEvent(language);
    }
}

function languageSuceess() {
    doOk("confirmblackBackground");
    UpgradeFlag = 0;
    changeLanguageEvent(confirmlanguage);
}

function changeLanguageEvent(language) {
    var Form = new webSubmitForm();
    Form.addParameter('language', language);
    Form.addParameter('x.X_HW_Token', getAuthToken(true));
    Form.setAction('setlanguage.cgi?'+'&RequestFile=index.asp');
    Form.submit(); 
}

function selectDropUp(){
    var iframewindow = document.getElementById('functioncontent').contentWindow;
    var dropList = iframewindow.document.getElementsByName('dropDownList');
    iframewindow.g_selectAllclickshow = false;
    for(var i = 0; i< dropList.length; i++){
        dropList[i].classList.add("noneDisplay");
        dropList[i].previousSibling.style.backgroundImage ="url('../../../images/arrow-down.png')";
    }
}

function psdStrength(ele) {
    document.getElementById("functioncontent").contentWindow.psdStrength(ele);
}

function changePassword(ele) {
    document.getElementById("functioncontent").contentWindow.changePassword(ele);
}

function AddKnownDevice() {
    document.getElementById("functioncontent").contentWindow.AddKnownDevice();
}

function AddKnownLanDevice() {
    document.getElementById("functioncontent").contentWindow.AddKnownLanDevice();
}
function selectDaysSelValue(ele) {
    document.getElementById("functioncontent").contentWindow.selectDaysSelValue(ele);
}

function ChooseSSIDSelValue(ele) {
    document.getElementById("functioncontent").contentWindow.ChooseSSIDSelValue(ele);
}
function ChooseStatusSelValue(ele) {
    document.getElementById("functioncontent").contentWindow.ChooseStatusSelValue(ele);
}
function GetSelectVal(id, array) {
    return document.getElementById("functioncontent").contentWindow.GetSelectVal(id, array);
}

function scheduleSave() {
    document.getElementById("functioncontent").contentWindow.scheduleSave();
}

function SaveBoostTime() {
    document.getElementById("functioncontent").contentWindow.SaveBoostTime();
}

function WlanBasicSubmit() {
    hideWifiBlock();
    document.getElementById("functioncontent").contentWindow.WlanBasicSubmit();
}

function resetPassword() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.resetPassword();
}

function deletNameList() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.deletNameList();
}

function uploadImage() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.uploadImage();
}

function Reboot() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.Reboot();
}

function deletMacline() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.deletMacline();
}

function deletDevListFun() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.deletDevListFun();
}

function submitCheck() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.submitCheck();
}

function enableWifi7() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.enableWifi7();
}

function disableAll() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.disableAll();
}

function changeBWListMode() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.changeBWListMode();
}

function rebackBWListMode() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.rebackBWListMode();
}
function sucessNext() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.sucessNext();
}

function sucessSub(){
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.sucessSub();
}

function removeUsbInst(instId) {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.removeUsbInst(instId);
}

function checkFTPServer() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.checkFTPServer();
}

function submitFtpData() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.submitFtpData();
}

function mergeSSIDConfirm() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.mergeSSIDConfirm();
}

function mergeSSIDSubmit() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.mergeSSIDSubmit();
}

function checkNeedMerge() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.checkNeedMerge();
}

function SetTransparentMode() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.SetTransparentMode();
}
 
function CancleConfig() {
    doOk("confirmblackBackground");
    document.getElementById("functioncontent").contentWindow.CancleConfig();
}

function getRadioValue(sId) {
    var item;
    if (null == (item = getElement(sId))) {
        debug(sId + " is not existed" );
        return -1;
    }

    if (item.length > 0) {
        for (i = 0; i < item.length; i++) {
            if (item[i].checked == true) {
                return item[i].value;
            }
        }
    } else if (item.checked == true) {
        return item.value;
    }

    return -1;
}

function hideWifiBlock() {
    document.getElementById("wifiBackground").style.display = "none";
    document.getElementById("wifiContent").style.display = "none";
}

function CancelGuestDuration() {
    document.getElementById("wifiBackground").style.display = "none";
    document.getElementById("wifiContent").style.display = "none";
    document.getElementById("functioncontent").contentWindow.CancelGuestDura();
    
}

function CancelAlertWifi() {
    if (document.getElementById("wifiContent").style.display == "none") {
        document.getElementById("wifiBackground").style.display = "none";
    }
    document.getElementById("wifiAlerrt").style.display = "none";
}

function AlertVDFWifi(value) {
    document.getElementById("wifiBackground").style.display = "";
    document.getElementById("wifiAlerrt").style.display = "";
    document.getElementById("alertContent").innerHTML = value;
}

function goToTop(){
    document.body.scrollIntoView();
}
</script>
</head>
<body onload="LoadFrame();" onclick = 'selectDropUp()'>
<div class="blackBackgroundWifi" id="wifiBackground" style="display:none;">
    <div class="popupWifi big add" id="wifiContent" style="display:none;">
        
    </div>
    <div id="wifiAlerrt" class="alertpopupwifi" style="display:none;z-index:200px;">
        <div class="alerttext">
            <span id="alertContent"></span>
        </div>
        <div class="alertpop">
            <input type="button" value="OK" onclick="CancelAlertWifi();" class="button button-apply W100">
        </div>
    </div>
</div>
<div id="look_3" class="lang-en mode-expert navigation-3of8 product-31 gateway-29" data-mode="mode-expert" data-language="lang-en" data-navigation-count="8">
    <div class="rel">
        <div id="header">
            <div class="rel">   
                <div id="top-bar">
                    <div id="top-bar-content">
                        <div id="logo_title" onclick="turnOverview(this.id)" BindText="frame010"></div>
                        <script>
                            if (CfgMode == 'ODIDO2') {
                                document.getElementById('logo_title').setAttribute('BindText', 'frame010_ODIDO2');
                            }
                        </script>
                        <div id="top-info" class="">
                            <div id="top-info-logged-user">
                                <div class="page-loader-container load-once" data-page-alias="top-info" data-has-loaded="true" data-page-id="3402">
                                    <span class="language-string" id="users_logging" >
                                    <span id="areinuse"></span>
                                    </span>
                                </div>
                            </div>                                                                  
                            <div class="dropdownSelect">
                                <div class="dropdownShow" id="dropdownShow" onclick="showDropdown(event);"></div>
                                <ul class="dropdownHide" id="dropdownHide" style="display:none"></ul>
                            </div>
                        </div>
                        
                    </div>
                </div>
            </div>
            <div id="header-inner" class="clearfix">
                <div id="rhombus-wrap">
                    <a id="logo"></a>
                    <script>
                        if (CfgMode == 'ODIDO2') {
                            let logoPath = '../images/hw_logo.gif'
                            $('#logo').css("background-image", "url('"+ logoPath +"')");
                        }
                    </script>
                    <div id="rhombus"></div>
                </div>
                <div id="rhombus-navigation" class="clearfix">
                    <div class="rel">
                        <div id="navigation">
                            <ul class="clearfix" id="clearfixtest"></ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
        <div class="page-loader-container warning-messages" data-page-alias="warning-messages" data-page-id="3403">
            <div id="globalMessages">
                <div class="rel">
                    <div class="global-wrap">
                        <div class="head-message clearfix" id="psdNote" style="display: none;">
                            <div class="fL">
                                <span BindText="amp_wifi_basic_ptvdf2_tr181_alert_psd_note"></span>
                            </div>
                            <div class="head-button-message-wrap">
                                <input type="button" value="dismiss" BindText="dismiss" id="dismiss" class="button button-cancel button-blank head2" onclick="dismissWifiPwdNote()">
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div id="content-wrap" class="clearfix rel">
            <div id="indicator" class="visible" style="top: 67px;">
                <div id="indicator-content"></div>
            </div>  
            <div id="subnavigation">
                <div class="subnavigation-ALL" id="subnavigation_id"></div>
            </div>

                    <div id="content-reset-wrap" class="clearfix">
                        <div class="white-background">
                            <div id="content" class="content-ipv6-firewall-rules">
                                <iframe id="functioncontent" frameborder="0" width="100%" height="370" marginheight="0" marginwidth="0" class="AspWidth" allowtransparency="true" scrolling="no" overflow="hidden" src="" style="z-index:301;position: relative;min-height:700px"></iframe>
                            </div>
                            <div id="fresh">
                                <iframe frameborder="0" width="100%" height="100" marginheight="0" marginwidth="0" scrolling="no" src="refresh.asp"></iframe>
                            </div>
                        </div>
                    </div>
                </div>
                <div id="footer">
                    <div id="language-info" class="clearfix">
                        <ul id="language-switcher-list">
                            <li class="language-switcher" data-language-id="4">
                                <a href="#" onClick="onChangeLanguage('english')" BindText="frame019"></a>
                            </li>
                            <li class="language-switcher" data-language-id="5">
                                <a href="#" onClick="onChangeLanguage('portuguese')" BindText="frame020"></a>
                            </li>
                        </ul>
                        <div class="page-loader-container load-once" data-page-alias="bottom-info" data-has-loaded="true" data-page-id="3505">
                            <div id="info">
                                <span class="language-string">
                                    <span BindText="frame024"></span><i id="soft_time" style="font-style:normal"></i>
                                </span><br>
                                <span id="ipv4address" class="language-string">
                                    <span BindText="frame025"></span><i id="ip4_address" style="font-style:normal"></i>
                                </span><br> 
                                <span id="ipv6address" class="language-string" >
                                    <span BindText="frame026"></span><i id="ip6_address" style="font-style:normal"></i>
                                </span><br> 
                                <span id="conneuptimestr" class="language-string">
                                    <span BindText="frame027"></span><i id="uptimestr" style="font-style:normal"></i>
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="blackBackground" id="indexblackBackground" style="display:none;"></div>
        <div class="blackBackground" id="alertblackBackground" style="z-index:301;display:none;">
            <div id="alertFrom" class="alertpopup">
                <div class="alerttext"><span id="alertspan"></span></div>
                <div class="alertpop"><input id="alertbtn" type="button" value="OK" onclick="doOk('alertblackBackground')" class="button button-apply W100"/></div>
            </div>
        </div>
        <div class="blackBackground" id="confirmblackBackground" style="z-index:301;display:none;">
            <div id="confirmFrom" class="alertpopup">
                <p class="title"><span id="confirmtitle"></span></p>
                <div class="alerttext"><span id="confirmspan"></span></div>
                <div class="confirmpop">
                    <input id="confirmokbtn" type="button" value="Apply" onclick="" class="button button-apply W100"/>
                    <input id="confirmnobtn" type="button" value="Cancel" onclick="doOk('confirmblackBackground')" class="button button-cancel W100"/>
                </div>
            </div>
        </div>
        <div class="blackBackground" id="informblackBackground" style="z-index:301;display:none;">
            <div id="informFrom" class="alertpopup">
                <div class="row"><img src="../../../images/icon-thinking.gif" alt="Loading..."></div>
                <p class="title"><span id="informtitle"></span></p>
                <div class="alerttext"><span id="informspan"></span></div>
            </div>
        </div>
        <div class="blackBackground" id="progressblackBackground" style="z-index:301;display:none;">
            <div id="progressFrom" class="alertpopup">
                <p class="title"><span id="progresstitle"></span></p>
                <div class="alerttext"><span id="progressspan"></span></div>
                <div id="progress-bar-box"><div id="progress-bar-image"></div></div>
            </div>
        </div>
        <div class="blackBackground" id="staticprogressblackBackground" style="z-index:301;display:none;">
            <div id="staticprogressFrom" class="alertpopup">
                <p class="title"><span id="staticprogresstitle"></span></p>
                <div class="alerttext"><span id="staticprogressspan"></span></div>
                <div class="row"><img src="images/progress.gif"></div>
            </div>
        </div>
        <div class="blackBackground" id="alertExblackBackground" style="z-index:301;display:none;">
            <div id="alertExFrom" class="alertpopup">
                <p class="title"><span id="alertExtitle"></span></p>
                <div class="alerttext"><span id="alertExspan"></span></div>
                <div class="confirmpop"><input id="alertExbtn" type="button" value="OK" onclick="doOk('alertExblackBackground')" class="button button-apply W100"/></div>
            </div>
        </div>
        <script language="javascript" src="/html/bbsp/common/getWanDynamicData.asp"></script>
    </body>
<script type="text/javascript">

function doOk(id) {
    document.getElementById(id).style.display = "none";
}
function setIframeHeight(iframeid) {
    try{
        var iframe = document.getElementById(iframeid);
        if (iframe.attachEvent) {
            try {
                var doc = iframe.contentDocument || iframe.document;
                var newheigth = iframe.contentWindow.document.documentElement.scrollHeight;
                var Bodyheigth = doc.body.clientHeight; 
            } catch(e) {
                var newheigth = 370;
                return;
            }

            newheigth = newheigth > 370 ? newheigth : 370;
            newheigth = Bodyheigth < 370 ? 370 : Bodyheigth;

            iframe.attachEvent("onload", function(){
                iframe.height =  newheigth;
                return;
            });

            iframe.height =  newheigth;
            return;
        } else {
            try {
                var newheigth = iframe.contentDocument.body.scrollHeight;
                var doc = iframe.contentDocument || iframe.document;
                var Bodyheigth = doc.body.clientHeight; 
                newheigth = newheigth > 370 ? newheigth : 370;
                newheigth = Bodyheigth < 370 ? 370 : Bodyheigth;
            } catch(e) {
                return ;
            }

            iframe.onload = function(){
                iframe.height = newheigth;
                return;
            };

            iframe.height = newheigth;
            return;
        }
    }catch(e){
        return;
    }
}
var curLanguage = 'portuguese';
function getMenuStrDefLen(level) {
    var length = 0;
    if(curLanguage.toUpperCase() == "ENGLISH") {
        if (level == "first" ) {
            length = 24;
        } else {
            length = 22;
        }
    } else {
        if (level == "first" ) {
            length = 22;
        } else {
            length = 20;
        }
    }
    return length;
}

function GetMenuTitle(datastr, level, element) {
    var length = getMenuStrDefLen(level);
    var titlestr = "";
    if (datastr.length > length) {
        titlestr = ' title="' + datastr + '" ';
        if (element != null)
            element.setAttribute("title", datastr);
    }
    return titlestr;
}

function stMenuData(id, path, level, defico, clickico, url, defchild)
{
    this.id         = id;
    this.path       = ((path == '') ? '' : (path + '.')) + id;
    this.level      = level;
    this.defico     = defico;
    this.clickico   = clickico;
    this.url        = url;
    this.defchild   = defchild;
    this.hasChild   = false;
}

function CreateSecondMenu(parentId, parentPath, subMenus,IsShowThirdMenu) {
    var MenuSecondList = [];
    SecondTmpMenuStr = "";
    SecondTmpMenuStr +='<ul class="sub-navigation" ID="UL_' + parentId + '">';

    for (var i in subMenus) {
        var id = subMenus[i].id;
        var name = subMenus[i].name
        var MenuStr = GetMenuStr(name, 22);
        var contenttitle ='<h3 id="title_'+ id + '" class="text-up">'+ subMenus[i].name + '</h3>';
        SecondTmpMenuStr +='<li id="Child' + id + '"><a id="' + id + '" class="second_click" title="' + subMenus[i].name +'" onclick="onSecondMenuChange(this.id,null);">'+ MenuStr +'</a></li>';   
        MenuSecondList[id] = new stMenuData(id, parentPath, 2,
                                      subMenus[i].deficon,
                                      subMenus[i].clickicon,
                                      subMenus[i].url, id);

        g_AllListMenuForJump[id] = new stMenuData(id, parentPath, 2,
                                                subMenus[i].deficon,
                                                subMenus[i].clickicon,
                                                subMenus[i].url, id);

        if (subMenus[i].subMenus != undefined) {
            CreateThirdMenu(id, MenuSecondList[id].path, subMenus[i].subMenus,IsShowThirdMenu);
            InitThirdMenuForJump(id, MenuSecondList[id].path, subMenus[i].subMenus);
            MenuSecondList[id].hasChild = true;
        }

        SecondMenuArray[id] = new stSecondMenuTitle(id, contenttitle, subMenus[i].url, MenuSecondList[id].hasChild);
    }
    SecondTmpMenuStr +="</ul>";
    
    if (true != IsShowThirdMenu) {
        return;
    }

    $("#subnavigation_id").append(SecondTmpMenuStr);

    for (var i in SecondMenuArray) {
        if (true != SecondMenuArray[i].hasChild) {
            continue;
        }

        try{
            var IndexId = SecondMenuArray[i].id;
            var appendId = g_ThirdMenuArry[IndexId].ChildId;
            var appendData = g_ThirdMenuArry[IndexId].MenuInfoList;
            $("#"+appendId).append(appendData);
        } catch(e) {
            continue;
        }
    }
}

function CreateThirdMenu( parentId, parentPath, subMenus,IsShowThirdMenu)
{
    if (false == IsShowThirdMenu) {
        return;
    }

    var MenuStrTemp = "";
    var ChildLiId = "Child"+parentId;
    MenuStrTemp +='<ul id="list_' + parentId + '" class="thirdClass" style="display:none">';
    var MenusLenth = subMenus.length - 1;
    for (var i in subMenus) {
        var id = subMenus[i].id; 
        g_MenuList[id] = new stMenuData(id, parentPath, 3,
                                      subMenus[i].deficon,
                                      subMenus[i].clickicon,
                                      subMenus[i].url, id);

        g_AllListMenuForJump[id] = new stMenuData(id, parentPath, 3,
                                       subMenus[i].deficon,
                                       subMenus[i].clickicon,
                                       subMenus[i].url, id);
        if (i == MenusLenth) {
            MenuStrTemp +='<li><a id="' + id + '" style="border-right:0;" title="' + subMenus[i].name +'" onclick="onThirdMenuChange(this.id,this.title);">'+ subMenus[i].name +'</a></li>';    
        } else {
            MenuStrTemp +='<li><a id="' + id + '" title="' + subMenus[i].name +'" onclick="onThirdMenuChange(this.id,this.title);">'+ subMenus[i].name +'</a></li>';    
        }
    }
    MenuStrTemp +='</ul>';

    g_ThirdMenuArry[parentId] = new stThirdMenuList(parentId, ChildLiId, MenuStrTemp);
}

function InitThirdMenuForJump( parentId, parentPath, subMenus) {
    var MenuStrTemp = "";
    var ChildLiId = "Child"+parentId;
    MenuStrTemp +='<ul id="list_' + parentId + '" class="thirdClass" style="display:none">';
    var MenusLenth = subMenus.length - 1;
    for (var i in subMenus) {
        var id = subMenus[i].id; 
        g_AllListMenuForJump[id] = new stMenuData(id, parentPath, 3,
                                       subMenus[i].deficon,
                                       subMenus[i].clickicon,
                                       subMenus[i].url, id);
    }
}
var FirstPageId = "OverviewID";
var FirstPageURL = "";

var menuAllButtonLength = 0;
for(var FirstMenuIndex in InstallNodeMenu) {
    var menuButtonlength = InstallNodeMenu[FirstMenuIndex].name.length;
    menuAllButtonLength += menuButtonlength
}

var lastMenuLength = 950;
for (var FirstMenuIndex in InstallNodeMenu) {
    var m1namesr = GetIdByUrl("m1div",InstallNodeMenu[FirstMenuIndex].url);
    var id = InstallNodeMenu[FirstMenuIndex].id;
    var MenuButtonLength = parseInt((940 * InstallNodeMenu[FirstMenuIndex].name.length) / menuAllButtonLength);
    if (FirstMenuIndex == InstallNodeMenu.length - 1) {
        MenuButtonLength = lastMenuLength;
    } else {
        lastMenuLength = lastMenuLength - MenuButtonLength;
    }
    var MenuButtonWidth = MenuButtonLength + "px;";

    FirstMenuStr += '<li style="width: '+ MenuButtonWidth +'"><a class="item" id="' + id + '" name="' + m1namesr + '" title="' + InstallNodeMenu[FirstMenuIndex].name +'" onclick="onFirstMenuChange(this.id,null);">' + InstallNodeMenu[FirstMenuIndex].name +'</a>';
    g_MenuList[id] = new stMenuData(id, '', 1,
                                    InstallNodeMenu[FirstMenuIndex].deficon,
                                    InstallNodeMenu[FirstMenuIndex].clickicon,
                                    InstallNodeMenu[FirstMenuIndex].url, id);

    g_AllListMenuForJump[id] = new stMenuData(id, '', 1,
                                              InstallNodeMenu[FirstMenuIndex].deficon,
                                              InstallNodeMenu[FirstMenuIndex].clickicon,
                                              InstallNodeMenu[FirstMenuIndex].url, id);
 
    if(undefined != InstallNodeMenu[FirstMenuIndex].subMenus) {
        CreateSecondMenu(id, g_MenuList[id].path, InstallNodeMenu[FirstMenuIndex].subMenus,false);
        g_MenuList[id].hasChild = true;
    }

    if (id == FirstPageId && g_MenuList[id].hasChild == false) {
        $("#content-reset-wrap").css("width","1000px");
        $("#content-reset-wrap").css("margin-left","0px");
        FirstPageURL = InstallNodeMenu[FirstMenuIndex].url;
    }

    FirstMenuStr +="</ul>";
}

$("#clearfixtest").append(FirstMenuStr);
$("#functioncontent").attr("src", FirstPageURL);

var typeWord = 'TR181';
if (typeWord == "BR") {
    onFirstMenuChange("SettingsID", "FirmwareUpdateID");
    document.getElementById("ipv4address").style.display = "none";
    document.getElementById("ipv6address").style.display = "none";
    document.getElementById("conneuptimestr").style.display = "none";
}

function LoadFrame(){
    $('#clearfixtest').find("li").children('a').first().addClass('addFirstMenu');
    var ModeTypeStr = framedesinfo["frame022"];
    if (curUserType == "0") {
        ModeTypeStr = framedesinfo["frame021"];
    }
    $('#dropdownShow').html(ModeTypeStr);
    var ShowHtml = loginNum +  framedesinfo["frame008"];
    document.getElementById('areinuse').innerHTML = ShowHtml;
    
    var obj = document.getElementById("LANIPv4ID");
    showWifiPwdNote()
}

function setLv1MenuStyle(id, flag, ifOnlyChangeStyle) {
    var menu = g_AllListMenuForJump[id];
    if (flag) {
        $("#"+ id).addClass("addFirstMenu");

        if ((ifOnlyChangeStyle != null) && (ifOnlyChangeStyle == "onlyshow")){
            return menu;
        }
        if ((menu.defchild != menu.id)
            && menu.hasChild){
            return setLv2MenuStyle(menu.defchild, flag);
        }
    } else {
        $("#" + id).removeClass("addFirstMenu");
        $("#UL_" + id).css("display","none");
    }

    return menu;
}

function setLv2MenuStyle(id, flag, ifOnlyChangeStyle)
{
    var menu = g_AllListMenuForJump[id];
    var FirstParentId = menu.path.split('.')[0];
    var SecondParentId = menu.path.split('.')[1];
    if (flag) {
        setLv1MenuStyle(FirstParentId, flag, "onlyshow");

        if (!menu.hasChild){
            $("#" + id).addClass("third_click");
        }

        if ((ifOnlyChangeStyle != null) && (ifOnlyChangeStyle == "onlyshow")){
            
            onFirstMenuChange(FirstParentId,"onlyAppendArrayList");
            onSecondMenuChange(SecondParentId,menu.id);
            return menu;
        }

        if ((menu.defchild != menu.id) && menu.hasChild) {
            $("#" + id).removeClass("second_click");
            $("#" + id).addClass("third_click");
            return setLv3MenuStyle(menu.defchild, flag);
        } else {
            onFirstMenuChange(FirstParentId,menu.id);
        }
    } else {
        $("#" + id).remoceClass("second_click");
    }
    return menu;
}

function setLv3MenuStyle(id, flag) {
    var menu = g_AllListMenuForJump[id];

    if (id == "") {
        id="menuid_3";
    }

    if (flag) {
        var FirstParentID = menu.path.split('.')[0];
        var parentId = menu.path.split('.')[1];

        setLv2MenuStyle(menu.id, flag, "onlyshow");

        $("#"+id).addClass("third_click");
    } else {
        $("#"+id).removeClass("third_click");
    }
    return menu;
}

function deactiveMenuStyle(DeactiveId) {
    var id = DeactiveId;
    var menu = g_AllListMenuForJump[id];

    if (menu == null)
        return ;

    var ids = menu.path.split('.');
    switch(menu.level) {
        case 3:
            setLv3MenuStyle(ids[2], false);
        case 2:
            setLv2MenuStyle(ids[1], false);
        default:
            setLv1MenuStyle(ids[0], false);
    }
}

function activeMenuStyle(id) {
    var menu = g_AllListMenuForJump[id];
    if (menu == null) {
        return null;
    }

    var ids = menu.path.split('.');
    switch(menu.level) {
        case 3:
            menu = setLv3MenuStyle(ids[2], true);
            break;
        case 2:
            menu = setLv2MenuStyle(ids[1], true);
            break;
        default:
            menu = setLv1MenuStyle(ids[0], true);
            break;
    }
    return menu;
}

function changeCrossLvMenuStyle(oldId, newId) {
    var oldMenu = g_AllListMenuForJump[oldId];
    var newMenu = g_AllListMenuForJump[newId];

    if ((oldMenu == null) || (newMenu == null))
        return;

    if (oldMenu.level == newMenu.level) {
        switch (oldMenu.level) {
            case 3:
                var lv2id_o = oldMenu.path.split('.')[1];
                var lv2id_n = newMenu.path.split('.')[1];
                if (lv2id_o != lv2id_n) {
                    $("#" + lv2id_o + "_menu").addClass("Menuhide");
                    $("#" + lv2id_n + "_menu").removeClass("Menuhide");
                } else {
                    $("#pointer_" + lv2id_n).removeClass("SecondMenuPointer");
                    $("#pointer_" + lv2id_n).addClass("SecondMenuPointerBlock");
                }
            case 2:
                var lv1id_o = oldMenu.path.split('.')[0];
                var lv1id_n = newMenu.path.split('.')[0];
                if (lv1id_o != lv1id_n) {
                    $("#" + lv1id_o + "_subMenus").addClass("Menuhide");
                    $("#" + lv1id_n + "_subMenus").removeClass("Menuhide");
                }
            default:
                break;
        }
    }
    else if (oldMenu.level < newMenu.level)
    {
        var lv1id_n = newMenu.path.split('.')[0];
        var lv1id_o = oldMenu.path.split('.')[0];

        if (lv1id_o != lv1id_n)
            $("#" + lv1id_o + "_subMenus").addClass("Menuhide");
            $("#" + lv1id_n + "_subMenus").removeClass("Menuhide");
            $("#SecondMenuInfo").removeClass("Menuhide");
            $("#SecondMenuInfo").addClass("Menushow");
        if (newMenu.level > 2) {
            var lv2id = newMenu.path.split('.')[1];
            $("#" + lv2id + "_menu").removeClass("Menuhide");
        }
        if (oldMenu.level < 2) {
            expandFirstMenuTitle(false);
        }
    } else {
        if (oldMenu.level > 2) {
            var lv2id = oldMenu.path.split('.')[1];
            $("#"+lv2id+"_menu").addClass("Menuhide");
        }

        if (newMenu.level < 2) {
            var lv1id = oldMenu.path.split('.')[0];
            $("#" + lv1id + "_subMenus").addClass("Menuhide");
            $("#SecondMenuInfo").removeClass("Menushow");
            $("#SecondMenuInfo").addClass("Menuhide");
            expandFirstMenuTitle(true);
        } else {
            var lv1id_o = oldMenu.path.split('.')[0];
            var lv1id_n = newMenu.path.split('.')[0];
            if (lv1id_o != lv1id_n) {
                $("#" + lv1id_o + "_subMenus").addClass("Menuhide");
                $("#" + lv1id_n + "_subMenus").removeClass("Menuhide");
            }
        }
    }
}

function expandFirstMenuTitle(flag) {
    var id;
    var action = ((flag == true) ? "block" : "none");

    $('#MenuFirstLineMid').css("display", action);
    $('#MenuBottomLineMid').css("display", action);

    for (var tmp in g_AllListMenuForJump) {
        if (g_AllListMenuForJump[tmp].level != 1) continue;
        id = "name_" + g_AllListMenuForJump[tmp].id;
        $('#' + id).css("display", action);
    }
}

function turnOverview(ParaId) {
    location.reload();
}

function logoutCheck() {
    if (UpgradeFlag == 1) {
        alertVDF(framedesinfo["frame042"]);
    } else {
        logoutfunc();
    }
}

function showLogUsers() {
    var oSpan = document.getElementById('users_logging');
    var oStrong = oSpan.getElementsByTagName('strong')[0];
    oStrong.innerHTML = loginNum ;
}

function showDropdown(event) {
    var modeUlStr = (curUserType == sysUserType)?framedesinfo["frame021"]:framedesinfo["frame022"];
    $("#dropdownHide").html("<li>"+modeUlStr+"</li><li onclick='logoutCheck();' >"+ framedesinfo["frame023"] +"</li>")
    $("#dropdownHide").toggle(function(){
        if(false == g_clickshow){
            $('#dropdownShow').css("background-image","url('../images/arrow-up.png')");
            g_clickshow = true;
        }else{
            g_clickshow = false;
            $('#dropdownShow').css("background-image","url('../images/arrow-down.png')");
        }
    });

    $("body").click(function(){
        $("#dropdownHide").hide();
        g_clickshow = false;
        $('#dropdownShow').css("background-image","url('../images/arrow-down.png')");
    });
    var e = window.event || event;
    if(e.stopPropagation){
        e.stopPropagation();
    }else{
        window.event.cancelBubble = true;
    }
}

var wanInfoAll = GetWanList();
var curIPv4Address = "- - - -";
var curIPv6Address = "- - - -";
var curWanMacId = ""

for (var i = 0; i < wanInfoAll.length; i++) {
    if ((wanInfoAll[i].ServiceList.toUpperCase().indexOf("INTERNET") >= 0) && (wanInfoAll[i].Status.toUpperCase() == "UP")) {
        curWanMacId = wanInfoAll[i].MacId;
        curIPv4Address = wanInfoAll[i].IPAddress;
        break;
    }
}

var curIPv6AddressList = GetIPv6AddressList(curWanMacId);
if (curIPv6AddressList.length != 0) {
    curIPv6Address = curIPv6AddressList[0].IPAddress;
}

$('#ip4_address').text(curIPv4Address);
$('#ip6_address').text(curIPv6Address);

$('#soft_time').text(SoftwareVersion);
$('#uptimestr').text(UpTimeStr);

var IframeOnclick = {
    resolution: 500,
    iframes:[],
    interval:null,
    Iframe:function(){
        this.element = arguments[0];
        this.cd = arguments[1];
        this.hasTracked = false;
    },
    track:function(element,cd){
        this.iframes.push(new this.Iframe(element,cd));
        if(!this.interval){
            var _this = this;
            this.interval = setInterval(function(){
                _this.checkClick();
            },this.resolution);
        }
    },
    checkClick:function(){
        if(document.activeElement){
            var activeElement = document.activeElement;
            for(var i in this.iframes){
                if(activeElement === this.iframes[i].element){
                    if(this.iframes[i].hasTracked ==  false){
                        this.iframes[i].cd.apply(window,[]);
                        this.iframes[i].hasTracked = true;
                    }
                }else{
                    this.iframes[i].hasTracked = false;
                }
            }
        }
    }
}

IframeOnclick.track(document.getElementById("functioncontent"),function(){
    $("#dropdownHide").hide();
})

function GetLanguageDesc(Name) {
    return framedesinfo[Name];
}

function isShowWifiPswTips() {
  var wlanPswData = getWlanPswData();

  if (!isWifiEnable(wlanPswData.LanDeviceArr)) {
    return false;
  }

  var wifiNameMap = {
    '2g': 'ath0',
    '5g': 'ath4',
    'guest2g': 'ath1',
    'guest5g': 'ath5',
  };
  for (var key in wifiNameMap) {
    var isStrong = checkSsidPsw(wifiNameMap[key], wlanPswData.WlanInfo, wlanPswData.wpaPskKey);
    if (!isStrong) {
      return true;
    }
  }
  return false;
}

function getWlanPswData() {
  var res = {};
  $.ajax({
    type: 'GET',
    async: false,
    cache: false,
    timeout: 10000,
    url: '/html/amp/ptvdf/getWlanPsw.asp',
    success: function(data) {
      res = dealDataWithFun(data);
    }
  });
  return res;
}

function isWifiEnable(LanDeviceArr) {
  var LanDevice = LanDeviceArr[0];
  var enbl = LanDevice.WlanCfg;
  return enbl === '1';
}

function checkSsidPsw(name, WlanInfo, wpaPskKey) {
  var ssidIdx = getSsidIdxByName(name, WlanInfo);
  if(ssidIdx < 0) {
    return true;
  }
  var ssidWlanInfo = WlanInfo[ssidIdx];

  if (ssidWlanInfo.enable !== '1') {
    return true;
  }

  var authMode = ssidWlanInfo.BeaconType;
  if (!isWlanModeHasPsw(authMode)) {
    return true;
  }

  var psw =  wpaPskKey[ssidIdx] && wpaPskKey[ssidIdx].value;
  if(!psw) {
    return true;
  }
  return isPswComplex(psw);
}

function getSsidIdxByName(name, WlanInfo) {
  return WlanInfo.findIndex(item => item && item.name === name);
}

function isWlanModeHasPsw(authMode) {
  var modeArrHasPsw = ['WPA', '11i', 'WPA2', 'WPAand11i', 'WPA/WPA2', 'WPA3', 'WPA2/WPA3'];
  return modeArrHasPsw.includes(authMode);
}

function isPswComplex(str) {
  var G_MIN_PSK_LENGTH = 12;
  if (str.length < G_MIN_PSK_LENGTH) {
    return false;
  }
  var lowerFlag = false;
  var upperFlag = false;
  var numberFlag = false;
  if (str.match(/[a-z]/)) {
    lowerFlag = true;
  }
  if (str.match(/[A-Z]/)) {
    upperFlag = true;
  }
  if (str.match(/\d/)) {
    numberFlag = true;
  }
  return (lowerFlag && upperFlag && numberFlag);
}

ParseBindTextByTagName(framedesinfo, "div",    1);
ParseBindTextByTagName(framedesinfo, "span",    1);
ParseBindTextByTagName(framedesinfo, "td",    1);
ParseBindTextByTagName(framedesinfo, "input",    2);
ParseBindTextByTagName(framedesinfo, "h1", 1);
ParseBindTextByTagName(framedesinfo, "a", 1);

function dismissWifiPwdNote() {
    document.getElementById("psdNote").style.display = "none";
}
function showWifiPwdNote() {
    if ((typeWord != "BR") && isShowWifiPswTips() && (curUserType == '1')) {
        document.getElementById("psdNote").style.display = "block";
    }else {
        dismissWifiPwdNote();
    }
}

</script>
</html>