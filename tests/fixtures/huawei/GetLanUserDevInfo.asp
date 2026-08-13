function USERDevice(Domain,IpAddr,MacAddr,Port,IpType,DevType,DevStatus,PortType,Time,HostName,IPv4Enabled,IPv6Enabled,DeviceType,UserDevAlias,UserSpecifiedDeviceType,LeaseTimeRemaining,RealMacAddr)
{
	this.Domain 	= Domain;
	this.IpAddr	    = (IpAddr.length == 0)?"--":IpAddr;
	this.MacAddr	= MacAddr;

	if(Port=="LAN0" || Port=="SSID0")
	{
		this.Port  = "--"; 
	}
	else
	{
		this.Port  = Port;
	}
	
	this.PortID = Port; 
	
	this.PortType	= PortType;
	
	this.DevStatus 	= DevStatus;
	this.IpType		= IpType;
	if(IpType=="Static")
	{
	  this.DevType="--";
	}
	else
	{
		if(DevType=="")
		{
			this.DevType	= "--";	
		}
		else
		{
			this.DevType	= DevType;		
		}	
	}
	this.Time	    = Time;
	
	if(HostName=="")
	{
		this.HostName	= "--";
	}
	else
	{
	   this.HostName	= HostName;
	}
	
	this.IPv4Enabled = IPv4Enabled;
	this.IPv6Enabled = IPv6Enabled;
	this.DeviceType = DeviceType;
	if (UserDevAlias == "")
	{
		this.UserDevAlias = "--";
	}
	else
	{
		this.UserDevAlias = UserDevAlias;
	}
	this.UserSpecifiedDeviceType = UserSpecifiedDeviceType;
	this.LeaseTimeRemaining = LeaseTimeRemaining;
	this.instid       = '';
	this.IsClickDev   = false;

    if (isRealmac == 1) {
        this.RealMacAddr = RealMacAddr;
    }
}

var ProductType = '1';
var isRealmac = '0';
if (ProductType == '2') {
    var UserDevinfo = new Array(new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.1","192\x2e168\x2e1\x2e11","02\x3a00\x3a00\x3a00\x3a00\x3a01","LAN1","Static","\x2d\x2d","Online","ETH","0\x3a14","","1","0","0","","0","0"),new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.2","192\x2e168\x2e1\x2e37","02\x3a00\x3a00\x3a00\x3a00\x3a02","SSID1","Static","\x2d\x2d","Offline","WIFI","28\x3a4","","1","0","0","","0","0"),new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.3","192\x2e168\x2e1\x2e1","02\x3a00\x3a00\x3a00\x3a00\x3a03","LAN1","Static","\x2d\x2d","Online","ETH","4\x3a52","","1","0","0","","0","0"),new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.4","192\x2e168\x2e1\x2e31","02\x3a00\x3a00\x3a00\x3a00\x3a04","LAN1","Static","\x2d\x2d","Offline","ETH","0\x3a6","","1","0","0","","0","0"),new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.5","0\x2e0\x2e0\x2e0","02\x3a00\x3a00\x3a00\x3a00\x3a05","SSID1","DHCP","","Offline","WIFI","29\x3a14","","0","1","0","","0","0"),new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.6","192\x2e168\x2e1\x2e84","02\x3a00\x3a00\x3a00\x3a00\x3a06","LAN1","Static","\x2d\x2d","Offline","ETH","0\x3a6","","1","0","0","","0","0"),null);
} else {
    var UserDevinfo = new Array(new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.1","192\x2e168\x2e1\x2e11","02\x3a00\x3a00\x3a00\x3a00\x3a01","LAN1","Static","\x2d\x2d","Online","ETH","0\x3a14","","1","0","0","","0","0","02\x3a00\x3a00\x3a00\x3a00\x3a01"),new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.2","192\x2e168\x2e1\x2e37","02\x3a00\x3a00\x3a00\x3a00\x3a02","SSID1","Static","\x2d\x2d","Offline","WIFI","28\x3a4","","1","0","0","","0","0","02\x3a00\x3a00\x3a00\x3a00\x3a02"),new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.3","192\x2e168\x2e1\x2e1","02\x3a00\x3a00\x3a00\x3a00\x3a03","LAN1","Static","\x2d\x2d","Online","ETH","4\x3a52","","1","0","0","","0","0","02\x3a00\x3a00\x3a00\x3a00\x3a03"),new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.4","192\x2e168\x2e1\x2e31","02\x3a00\x3a00\x3a00\x3a00\x3a04","LAN1","Static","\x2d\x2d","Offline","ETH","0\x3a6","","1","0","0","","0","0","02\x3a00\x3a00\x3a00\x3a00\x3a04"),new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.5","0\x2e0\x2e0\x2e0","02\x3a00\x3a00\x3a00\x3a00\x3a05","SSID1","DHCP","","Offline","WIFI","29\x3a14","","0","1","0","","0","0","02\x3a00\x3a00\x3a00\x3a00\x3a05"),new USERDevice("InternetGatewayDevice.LANDevice.1.X_HW_UserDev.6","192\x2e168\x2e1\x2e84","02\x3a00\x3a00\x3a00\x3a00\x3a06","LAN1","Static","\x2d\x2d","Offline","ETH","0\x3a6","","1","0","0","","0","0","02\x3a00\x3a00\x3a00\x3a00\x3a06"),null);
}

function stWifiWorkingMode(domain,WifiMode,IPAddress,MacAddress)
{
	this.domain 		= domain;
	this.WifiMode 		= WifiMode;
	this.IPAddress		= IPAddress;
	this.MacAddress     = MacAddress;
}

var WifiWorkingModes = new Array(new stWifiWorkingMode("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.AssociatedDevice.1","11n","","02\x3a00\x3a00\x3a00\x3a00\x3a07"),new stWifiWorkingMode("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.AssociatedDevice.2","11n","","02\x3a00\x3a00\x3a00\x3a00\x3a08"),new stWifiWorkingMode("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.AssociatedDevice.3","11n","","02\x3a00\x3a00\x3a00\x3a00\x3a09"),new stWifiWorkingMode("InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.AssociatedDevice.4","11n","0\x2e0\x2e0\x2e0","02\x3a00\x3a00\x3a00\x3a00\x3a05"),new stWifiWorkingMode("InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.AssociatedDevice.1","11ax","","02\x3a00\x3a00\x3a00\x3a00\x3a0a"),new stWifiWorkingMode("InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.AssociatedDevice.2","11ax","","02\x3a00\x3a00\x3a00\x3a00\x3a0b"),new stWifiWorkingMode("InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.AssociatedDevice.3","11ax","","02\x3a00\x3a00\x3a00\x3a00\x3a0c"),new stWifiWorkingMode("InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.AssociatedDevice.4","11na","","02\x3a00\x3a00\x3a00\x3a00\x3a0d"),null);
var curCfgModeWord ='PTVDF2WIFI_PWD'; 
var ttnet = '0';
if (curCfgModeWord == "TALKTALK2WIFI")
{
	for(var i = 0; i < UserDevinfo.length - 1; i++)
	{	var MACmacthFlag = 0; 
		if (UserDevinfo[i].DevStatus.toUpperCase() == "OFFLINE")
		{
			UserDevinfo[i].Port = "--";
			continue;
		}
		
		if(UserDevinfo[i].PortType != "WIFI")
		{		
			UserDevinfo[i].Port = "Ethernet";
			continue;
		}
		
		
		for(var j = 0;j < WifiWorkingModes.length - 1 ; j++)
		{ 
			if (UserDevinfo[i].MacAddr.toString().toUpperCase() ==  WifiWorkingModes[j].MacAddress.toString().toUpperCase())
			{	
				UserDevinfo[i].Port = WifiWorkingModes[j].WifiMode;	
				MACmacthFlag = 1;
				break;
			}	
		}
		
		if(MACmacthFlag != 1)
		{
			for(var k = 0;k < WifiWorkingModes.length - 1 ; k++)
			{
				if	(UserDevinfo[i].IpAddr.toString() == WifiWorkingModes[k].IPAddress.toString())
				{
					UserDevinfo[i].Port = WifiWorkingModes[k].WifiMode;	
					MACmacthFlag = 1;
					break;
				}
			}
		}
		if(MACmacthFlag != 1)
		{
			UserDevinfo[i].Port = "--";
		}
	}	
}



var UserDevinfoTmp = new Array();
for(var i = 0; i < UserDevinfo.length - 1; i++)
{
	var id = UserDevinfo[i].Domain.split(".");
	UserDevinfo[i].instid = id[id.length -1];

	if (UserDevinfo[i].IPv4Enabled == "1") {
		if (ttnet == '1') {
			if (UserDevinfo[i].DevStatus.toUpperCase() == "ONLINE") {
				UserDevinfoTmp.push(UserDevinfo[i]);
			}
		} else {
			UserDevinfoTmp.push(UserDevinfo[i]);
		}
	}
}
UserDevinfoTmp.push(null);

function GetUserDevInfoList()
{
	return UserDevinfoTmp;
}

GetUserDevInfoList();