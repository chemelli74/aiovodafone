<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Pragma" content="no-cache" />
<script language="JavaScript" src="../../../resource/common/util.js?03fa5651e1972f63229090335"></script>
<script language="JavaScript" src="../../../resource/common/InitForm.asp?03fa5651e1972f63229090335"></script>
<script language="JavaScript" src="../../../resource/lancutdes.js?03fa5651e1972f632290903352138485273"></script>
<script language="JavaScript" src='../../../Cusjs/InitFormCus.js?03fa5651e1972f63229090335'></script>
<script language="JavaScript" src="../../../resource/common/jquery.min.js?03fa5651e1972f63229090335"></script>
<link rel="stylesheet"  href='../../../resource/common/style.css?03fa5651e1972f63229090335' type='text/css'>
<link rel="stylesheet" href='../../../Cuscss/frame.css?03fa5651e1972f63229090335' type='text/css'>
<title>Phone Numbers</title>
<style type="text/css">
table.table-three-columns th {
  font-weight: normal;
  height: 30px;
  line-height: 30px;
  padding: 10px;
  text-align: left;
}
h1 {
    color: #e60000;
    font-family: "VodafoneRgRegular";
    font-size: 45px;
    font-weight: 350;
    line-height: 50px;
    margin-bottom: 10px;
}

h2 {
    font-size: 16px;
    font-weight: normal;
    margin-bottom: 30px;
    line-height: 24px;
}
h3 {
    color: #e60000;
    font-family: "VodafoneLtRegular";
    font-size: 28px;
    line-height: 50px;
    padding-left: 40px;
}
.h3-content th {
  border-bottom: 1px solid #e6e6e6;
}
.h3-content td, .h3-content th {
  font-weight: normal;
  height: 30px;
  line-height: 30px;
  padding: 10px;
  text-align: left;
  /*width: 33.3%;*/
}
.h3-content table.table-three-columns th {
  width: auto;
}
input.button {
  border-radius: 3px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.6);
  font-size: 16px;
  font-weight: bold;
  padding: 0 20px;
  height: 34px;
  line-height: 34px;
  background-color: #ffffff;
}
input.button.button-apply {
  background-color: #b141ad;
  color: #fff;
}
.apply-cancel input:last-of-type {
  margin-right: 0;
}
.wordclass
{
	word-wrap: break-word;
	word-break: break-all;
	max-width: 270px;
}
</style>

<script language="JavaScript" type="text/javascript">
var vagIndex = 0;
var vagLastInst = '0';

function stProfile(Domain, Enable)
{
    this.Domain = Domain;
    this.Enable = Enable;

}

var AllProfile = new Array(new stProfile("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1","Enabled"),null);
vagIndex = GetVagIndexByInst(vagLastInst);

function GetVagIndexByInst(vagInst)
{
    for(var i = 0; i < AllProfile.length-1; i++)
    {
        if(AllProfile[i].profileid == vagInst)
        {
            return i;
        }
    }
    return 0;
}

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
for (var i = 0; i < AllLineURI.length-1; i++) 
    LineURI[i] = AllLineURI[i];
	
var AllLine = new Array(new stLine("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.1","\x2b15555550100","1",""),new stLine("InternetGatewayDevice.Services.VoiceService.1.VoiceProfile.1.Line.2","line2","2",""),null);
var LineList = new Array(new Array(),new Array(),new Array(),new Array());

for (var i = 0; i < AllLine.length-1; i++)
{
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
for (var i = 0; i < AllAuth.length-1; i++) 
    Auth[i] = AllAuth[i];

var User = new Array();

function stUser(Domain, UserId)
{
    this.Domain = Domain;
    this.UserId = UserId;
}

for (var i = 0; i < AllLine.length - 1; i++)
{
    User[i] = new stUser();
    User[i].UserId = AllLine[i].DirectoryNumber;
}

var vdfPhoneNumber = new Array();
function  GetPhoneNumber(inputstring)
{
	if( inputstring.indexOf(":") >= 0)       
	{
		var URIpart = inputstring.split(':');
		var k1 = URIpart[1];
		var k2 = k1.split('@');
		var k3 = k2[0];
		if (k3 == "")
		{   
			number = "--";
		}
		else
		{    
			number = k3;
		}
	 }
	 else
	 {
		 var URIpart = inputstring.split('@');
		 var k = URIpart[0];
		if (k == "")
		{    
			number = "--";
		}
		else
		{   
			number = k; 
		}
	 }
	 return number;
}

for (i = 0; i < AllLine.length - 1; i++)
{
	if(AllLineURI[i].URI != "")
	{
		vdfPhoneNumber[i] = GetPhoneNumber(LineURI[i].URI);	
	}
	else if(AllLine[i].DirectoryNumber != "")
	{
		vdfPhoneNumber[i] = GetPhoneNumber(User[i].UserId);
	}
	else if(AllAuth[i].AuthUserName != "")
	{
		vdfPhoneNumber[i] = GetPhoneNumber(Auth[i].AuthUserName);
	}
	else
	{
		vdfPhoneNumber[i] = "--";
	}
}

var htmlDescriptionId = new Array();
for (i = 0; i < AllLine.length - 1; i++)
{
    htmlDescriptionId[i] = "Description" + i;	
}

function setVagInfo()
{
    if(AllProfile[0] == null)
    {
        return;
    }
	for (i = 0; i < AllLine.length - 1; i++)
	{
		setText(htmlDescriptionId[i], AllLine[i].X_HW_Description);
	}
}

function AddSubmitParam(Form,type)
{    
    var domain = "";
	var add = "";
	var des = "";
    if(AllProfile[0] == null)
    {
        return false;
    }

	domain ='x=' + AllProfile[vagIndex].Domain;
	for(i = 0; i < AllLine.length - 1; i++)
	{
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
    if (val.length > len)
    {
        AlertEx(cfgName + vdfsipline['vspa_cantexceed']  + len  + vdfsipline['vspa_characters']);
        return false;
    }        
}

function CheckForm(type)
{
    var ulret=0;  	
	var i = AllLine.length - 1;
	for(i = 0; i < AllLine.length - 1; i++) 
	{
		ulret |= CheckForm1(i); 
	}
    if (ulret != true )
    {
        return false;
    }
    
    return true;
}

function CheckForm1(index)
{ 
    if ( '' != removeSpaceTrim(getValue(htmlDescriptionId[index])))
    {
        if (vdfvspaisValidStrlen(vdfsipline['vspa_linedes'],getValue(htmlDescriptionId[index]),32) == false)
        {
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
	if(AllLine.length - 1 >= 1)    
	{
		setDisplay('PhoneNumApplyCancel', 1);
	}
}

</script>
</head>
<body class="mainbody" onload="LoadFrame();">
<div id="content" class="content-phone-numbers">
<h1>
  <span class="language-string" name="PAGE_PHONE_NUMBERS_TITLE"></span>
	<script language="JavaScript" type="text/javascript">
	  document.write(vdfsipline['vspa_vdfphonenums']);
	</script>
 </h1>
<h2>
  <span class="language-string" name="PAGE_PHONE_NUMBERS_SUBTITLE">
  	<script language="JavaScript" type="text/javascript">
	  document.write(vdfsipline['vspa_vdfphonenumdes']);
	</script>
  </span></h2>
<h3>
  <span class="language-string" name="PAGE_PHONE_NUMBERS_TABLE_1_TITLE">
    <script language="JavaScript" type="text/javascript">
	  document.write(vdfsipline['vspa_vdfyouphone']);
	</script>
   </span></h3>
    <div class="phoneNumbersContent">
      <div class="h3-content">
	  <form id="PhoneSetConfigForm1">
    <table class="table-three-columns">
      <thead>
      <tr>
        <th><span class="language-string" name="PAGE_PHONE_NUMBERS_TABLE_2_COLTITLE_1">
		  <script language="JavaScript" type="text/javascript">
			document.write(vdfsipline['vspa_vdfconnect']);
		  </script>
		</span></th>
        <th><span class="language-string" name="PAGE_PHONE_NUMBERS_TABLE_1_COLTITLE">
		  <script language="JavaScript" type="text/javascript">
			document.write(vdfsipline['vspa_vdfphonenum']);
		  </script>
        </span></th>
        <th><span class="language-string" name="PAGE_PHONE_NUMBERS_TABLE_1_COLTITLE_2">
		  <script language="JavaScript" type="text/javascript">
			document.write(vdfsipline['vspa_vdfname']);
		  </script>
		</span></th>
      </tr>
      </thead>
      <tbody>
	    <script language="JavaScript" type="text/javascript">
		if(AllLine.length - 1 == 0)  
		{
			document.write('<tr>');
			document.write('<td> --</td>');			 
			document.write('<td> --</td>');	
			document.write('<td>');
			document.write('<input  type="text" class="no-specials" maxlength="32" value=" "/>');
			document.write('</td>');
			document.write('</tr>');
		}
		for(i = 0; i < AllLine.length - 1; i++)
		{
			document.write('<tr>');
			document.write('<td>' + vdfsipline['vspa_vdfTel'] + ' ' + htmlencode(AllLine[i].PhyReferenceList) + '</td>');							
			document.write('<td class="wordclass" >' + htmlencode(vdfPhoneNumber[i]) + '</td>');	
			document.write('<td>');
			document.write('<input id=' +htmlDescriptionId[i] + ' type="text" class="no-specials" maxlength="32" />');
			document.write('</td>');
			document.write('</tr>');
		}
		</script> 
      </tbody>
  </table>
</form>
</div>

<table>
<div id="PhoneNumApplyCancel" class="clearfix apply-cancel" style="display:none">
        <input type="hidden" name="onttoken" id="hwonttoken" value="0606060606060606060606060606060606060606060606060606060606060606">
        <input name="SaveApply_button" id="SaveApply_button" type="button" class="button button-apply" value="Apply" onClick="Submit();"/> 
          <script type="text/javascript">
          document.getElementsByName('SaveApply_button')[0].value = vdfsipline['vspa_vdfapply'];  
          </script>
        <input name="Cancel_button" id="Cancel_button" type="button" class="button button-cancel" value="Cancel" onClick="ButtonCancel();"/> 
          <script type="text/javascript">
              document.getElementsByName('Cancel_button')[0].value = vdfsipline['vspa_vdfcancel'];  
          </script> 
</div>
</table>
<table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr><td class="height10p"></td></tr>
</table>

</body>
</html>
