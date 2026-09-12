function() {
  var IPWanList = new Array(new WanIP("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1","0","0","AlwaysOn","","Connected","","","Internet","1","","","Connected","IP\x5fRouted","DHCP","203\x2e0\x2e113\x2e10","255\x2e255\x2e128\x2e0","","1","","192\x2e168\x2e1\x2e31\x2c192\x2e168\x2e1\x2e31","","","","","","Internet","","0","1","1","1","","","","","","","","","","","","105233","1",""),new WanIP("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.2.WANIPConnection.1","0","0","AlwaysOn","","Connected","","","VoIP","1","","","Connected","IP\x5fRouted","DHCP","198\x2e51\x2e100\x2e10","255\x2e255\x2e192\x2e0","","1","","192\x2e0\x2e2\x2e1\x2c192\x2e0\x2e2\x2e2","","","","","","VoIP","","0","2","1","0","","","","","","","","","","","","105230","0",""),new WanIP("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.3.WANIPConnection.1","0","0","AlwaysOn","","Connected","","","IPTV","1","","","Connected","IP\x5fRouted","DHCP","198\x2e51\x2e100\x2e20","255\x2e255\x2e128\x2e0","","1","","192\x2e0\x2e2\x2e3\x2c192\x2e0\x2e2\x2e4","","","","","","IPTV","","0","3","1","0","","","","","","","","","","","","105228","0",""),null);
  var PPPWanList = new Array(null);
  
  var IPWanListNum = IPWanList.length - 1;
  var PPPWanListNum = PPPWanList.length - 1;
  var WanIdx = 0;
  var WanList = new Array();
  
  for(var i=0; (IPWanList != null && IPWanListNum > 0 && i < IPWanListNum);i++)
  {		
    WanList[WanIdx] = new WanInfoInst();
    ConvertIPWan(IPWanList[i], WanList[WanIdx]);
    WanIdx++;
  }
  
  for(var j=0; (null != PPPWanList && PPPWanListNum > 0 && j < PPPWanListNum); j++)
  {	
    WanList[WanIdx] = new WanInfoInst();
    ConvertPPPWan(PPPWanList[j], WanList[WanIdx]);
    WanIdx++;
  }
  
  function IPv6AddressInfo(domain, IPAddressStatus, Origin,IPAddress,PreferredTime,
                          ValidTime,ValidTimeRemaining)
  {
      this.WanInstanceId = domain.split(".")[4];
      this.IPAddressStatus = IPAddressStatus;
      this.Origin = Origin;
      this.IPAddress = IPAddress;
    this.PreferredTime = PreferredTime;
    this.ValidTime = ValidTime;
    this.ValidTimeRemaining = ValidTimeRemaining;
  }
  
  var IPv6AddressList =  new Array(new IPv6AddressInfo("InternetGatewayDevice.WANDevice.1.X_HW_ShowInterface.1.IPv6Address.1","","None","2001\x3adb8\x3a1\x3a1\x3a\x3a1","","",""),new IPv6AddressInfo("InternetGatewayDevice.WANDevice.1.X_HW_ShowInterface.1.IPv6Address.2","","LinkLocal","fe80\x3a\x3a0000\x3a00ff\x3afe00\x3a0001","","",""),null);
  
  function IPv6WanInfo(domain, Type, ConnectionStatus, L2EncapType, MACAddress, Vlan, Pri,
                       DNSServers, AFTRName, AFTRPeerAddr,DefaultRouterAddress,V6UpTime)
  {
      this.WanInstanceId = domain.split(".")[4];
      this.Type = Type;
      this.ConnectionStatus = ConnectionStatus;
      this.L2EncapType = L2EncapType;
      this.MACAddress = MACAddress;
      this.Vlan = Vlan;
      this.Pri = Pri;
    this.DNSServers = DNSServers;
    this.AFTRName = AFTRName;
    this.AFTRPeerAddr = (AFTRPeerAddr=="::")?"":AFTRPeerAddr;
    this.DefaultRouterAddress = DefaultRouterAddress;
      this.V6UpTime = V6UpTime;
  }
  
  var IPv6WanInfoList =  new Array(new IPv6WanInfo("InternetGatewayDevice.WANDevice.1.X_HW_ShowInterface.1","WAN","Connected","IPoE","","","","","","","",""),new IPv6WanInfo("InternetGatewayDevice.WANDevice.1.X_HW_ShowInterface.2","WAN","Invalid","IPoE","","","","","","","",""),new IPv6WanInfo("InternetGatewayDevice.WANDevice.1.X_HW_ShowInterface.3","WAN","Invalid","IPoE","","","","","","","",""),null);
  
  
  function AllWanInfoSt()
  {
    this.WanList = new Array(null);
    this.IPv6AddressList = new Array(null);
    this.IPv6WanInfoList = new Array(null);
  }
  var AllWanInfo = new AllWanInfoSt('','','');
  AllWanInfo.WanList = WanList;
  AllWanInfo.IPv6AddressList = IPv6AddressList;
  AllWanInfo.IPv6WanInfoList = IPv6WanInfoList;
  

  return AllWanInfo;
}
