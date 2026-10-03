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
function IPv6PrefixInfo(domain, Origin, Prefix,PreferredTime,ValidTime,ValidTimeRemaining)
{
    this.WanInstanceId = domain.split(".")[4];
    this.Prefix = Prefix;
    this.Origin = Origin;
	this.PreferredTime = PreferredTime;
	this.ValidTime = ValidTime;
	this.ValidTimeRemaining = ValidTimeRemaining;
}

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

var IPv6AddressList = [];
var IPv6PrefixList = [];
var IPv6WanInfoList = [];

function GetIPv6AddressList(WanInstanceId)
{
    var List = new Array();
    var Count = 0;
    
    for (var i = 0; i < IPv6AddressList.length; i++)
    {
        if(IPv6AddressList[i] == null)
        continue;
        
        if (IPv6AddressList[i].WanInstanceId != WanInstanceId)
        continue;
        
        List[Count++] = IPv6AddressList[i];
    } 
    
    return List;
}

function GetIPv6PrefixList(WanInstanceId)
{
    var List = new Array();
    var Count = 0;
    
    for (var i = 0; i < IPv6PrefixList.length; i++)
    {
        if(IPv6PrefixList[i] == null)
        continue;
        
        if (IPv6PrefixList[i].WanInstanceId != WanInstanceId)
        continue;
        
        List[Count++] = IPv6PrefixList[i];
    } 
    
    return List;
}

function GetIPv6WanInfo(WanInstanceId)
{
    for (var i = 0; i < IPv6WanInfoList.length; i++)
    {
        if (IPv6WanInfoList[i] != null)
        {
            if (IPv6WanInfoList[i].WanInstanceId == WanInstanceId)
            {
                return IPv6WanInfoList[i];
            }
        }
    }    
}

(function() {
  var wanCacheObj = window.parent.wanCacheObj;
  if (
      (typeof wanCacheObj !== 'undefined')
      && (typeof wanCacheObj.wanIpv6StateCacheObj !== 'undefined')
      && (JSON.stringify(wanCacheObj.wanIpv6StateCacheObj) !== '{}')
    ) {
    var ipv6StateCache = wanCacheObj.wanIpv6StateCacheObj;
    IPv6AddressList = ipv6StateCache.IPv6AddressList;
    IPv6PrefixList = ipv6StateCache.IPv6PrefixList;
    IPv6WanInfoList = ipv6StateCache.IPv6WanInfoList;
  } else {
    var result = ajaxGetAspData('/html/bbsp/common/wan_list_cache_wanipv6.asp');
    IPv6AddressList = result.IPv6AddressList;
    IPv6PrefixList = result.IPv6PrefixList;
    IPv6WanInfoList = result.IPv6WanInfoList;
    if (window.parent.wanCacheObj) {
      window.parent.wanCacheObj.wanIpv6StateCacheObj = result;
    }
  }
})();
