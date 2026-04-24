# Wireshark Evidence Guide

Capture supporting evidence for:

- baseline plaintext HTTP traffic from CGM to gateway
- attacker in-path traffic during ARP spoofing
- `/api/glucose` JSON payload visibility

## Network Values

Use the active lab addresses:

```text
CGM node IP:       <cgm_ip_address>
Gateway node IP:   <gateway_ip_address>
Attacker node IP:  <attacker_ip_address>
Gateway port:      5050
```

## Capture Locations

- CGM node: baseline and CGM-side traffic
- Attacker node: ARP spoofing and in-path traffic
- Gateway VM: traffic received by the gateway

Install tcpdump on the attacker node if needed:

```bash
sudo apt install -y tcpdump
```

## Baseline Capture

1. Start capture on the CGM node network interface.
2. Apply this display filter:

```text
ip.addr == <gateway_ip_address> && tcp.port == 5050
```

3. Start the gateway:

```bash
python3 threat_model_mitm/src/main_cgm_api.py --mode gateway
```

4. Start the CGM sender:

```bash
python3 threat_model_mitm/src/main_cgm_api.py --mode cgm --gateway-ip <gateway_ip_address> --interval 1 --no-loop
```

5. Screenshot packet list and HTTP details for `POST /api/glucose`.

## Attack Capture

1. Start tcpdump on the attacker node:

```bash
sudo tcpdump -i <network_interface> 'arp or (host <cgm_ip_address> and host <gateway_ip_address> and tcp port 5050)' -w mitm_attack.pcap
```

2. Start the gateway:

```bash
python3 threat_model_mitm/src/main_cgm_api.py --mode gateway
```

3. Start the attacker:

```bash
cd threat_model_mitm/src/machine3_attacker
sudo python3 run_attack.py
```

4. Start the CGM sender:

```bash
python3 threat_model_mitm/src/main_cgm_api.py --mode cgm --gateway-ip <gateway_ip_address> --interval 1 --no-loop
```

5. Stop tcpdump with `Ctrl+C` and open `mitm_attack.pcap` in Wireshark.

## Useful Filters

ARP evidence:

```text
arp
```

Gateway API traffic:

```text
tcp.port == 5050
```

ARP plus CGM/gateway traffic:

```text
(ip.addr == <cgm_ip_address> && ip.addr == <gateway_ip_address>) || arp
```

Decoded HTTP endpoint:

```text
http.request.uri contains "/api/glucose"
```

Raw TCP fallback:

```text
tcp contains "/api/glucose"
tcp contains "glucose_mmol"
```
