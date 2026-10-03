function() {
  function stWlan(domain, enable, name, BeaconType) {
    this.domain = domain;
    this.enable = enable;
    this.name = name;
    this.BeaconType = BeaconType;
  }
  var WlanInfo = dealArrayIfEmpty(new Array(new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1","1","ath0","11i"),new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e2","0","ath1","11i"),new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e3","0","ath2","WPA3"),new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e4","0","ath6","WPA3"),new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e5","1","ath4","11i"),new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e6","0","ath5","11i"),null));

  function stPreSharedKey(domain, psk, kpp) {
    this.domain = domain;
    this.value = psk;

    if (kppUsedFlag === '1') {
      this.value = kpp;
    }
  }
  var kppUsedFlag = '0';
  var wpaPskKey = dealArrayIfEmpty(new Array(new stPreSharedKey("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1\x2ePreSharedKey\x2e1","REDACTED",""),new stPreSharedKey("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e2\x2ePreSharedKey\x2e1","REDACTED",""),new stPreSharedKey("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e3\x2ePreSharedKey\x2e1","REDACTED",""),new stPreSharedKey("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e4\x2ePreSharedKey\x2e1","REDACTED",""),new stPreSharedKey("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e5\x2ePreSharedKey\x2e1","REDACTED",""),new stPreSharedKey("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e6\x2ePreSharedKey\x2e1","REDACTED",""),null));

  function stLanDevice(domain, WlanCfg) {
    this.domain = domain;
    this.WlanCfg = WlanCfg;
  }
  var LanDeviceArr = dealArrayIfEmpty(new Array(new stLanDevice("InternetGatewayDevice\x2eLANDevice\x2e1","1"),null));

  function dealArrayIfEmpty(data) {
    if(data) {
      return data;
    }
    return [];
  }

  return {
    WlanInfo,
    wpaPskKey,
    LanDeviceArr,
  };
}
