  cat <<EOF | apoctl api create networkrulesetpolicy -n $MICROSEG_NS -f -
  name: block-malicious-ips
  description: Block connections with malicious IPs
  propagate: true
  subject:
    - - \$identity=processingunit
  outgoingRules:
    - action: Reject
      object:
        - - externalnetwork:name=malicious-ips
      protocolPorts:
        - any
  incomingRules:
    - action: Reject
      object:
        - - externalnetwork:name=malicious-ips
      protocolPorts:
        - any
    EOF