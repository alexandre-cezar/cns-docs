cat <<EOF | apoctl api create automation -n $MICROSEG_NS -f -
 name: create-and-update-malicious-ip-list
 trigger: Time
 schedule: "@every 12h"
 immediateExecution: true
 disabled: false

 parameters:
  serviceName: "malicious-ips"

 entitlements:
  externalnetwork:
    - retrieve-many
    - create
    - delete

 condition: |
  function when(api, params) {
    return {continue: true, payload: null};
  }

 actions:
  - |
    function then(api, params, payload) {
      serviceName = params.serviceName
      obj = aporeto.http('GET', 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt');

      lines = obj.body.split('\n');

      var maliciousIPs = [];
      for (i=0; i < lines.length; i++) {
        if (lines[i].slice(0,1) != "#")  {
          var parts = lines[i].split(/\s+/);
          if ( parseInt(parts[1]) > 7 ) {
            maliciousIPs.push(parts[0]+"/32")
          } else {
            break;
          }
        }
      }

      if (maliciousIPs.length > 0 ) {
        var definedServices = api.RetrieveMany('externalnetwork', null, 'name == '+serviceName);
        if (definedServices.length > 0) {
          api.Delete('externalnetwork', definedServices[0].ID)
        }
        api.Create('externalnetwork', {
          name: serviceName,
          description: "Automatically updated malicious IP list"
          entries: maliciousIPs,
          propagate: true,
          associatedTags : [
            "externalnetwork:name=malicious-ips",
          ]
        })
      }
    }
 EOF