# MITM Attack Experimentation Package

This repository contains a package named `mitm`, developed for our experimentation with Man-In-The-Middle (MITM) attacks. The package includes three essential modules: `atk.py`, `listen.py`, and `detect.py`. Here's a description of each module and its functionalities:

## Modules

### 1. atk.py (Attack Module)

- `arp()`: This function allows for the creation of forged ARP requests. The goal is to manipulate the ARP tables of target machines to redirect traffic towards the attacker. This enables the attacker to intercept and read network traffic between the client and the server.

- `dhcp()`: This function allows for the creation of forged DHCP responses, impersonating a legitimate DHCP server. Thus, the attacker can provide false network configuration information to the client, including a fake default router. This allows the attacker to redirect all client traffic towards themselves.

### 2. listen.py (Network Listening Module)

- `http()`: This function allows for listening to web traffic exchanged between the client and the server. The attacker can thus intercept HTTP requests and responses, and potentially collect sensitive information such as login credentials.

- `dns()`: This function allows for listening to DNS requests made by the client. The attacker can thus intercept DNS requests and potentially redirect the client to malicious servers.

### 3. detect.py (Attack Detection Module)

- `arp()`: This function uses a method similar to that used by the Arpwatch tool. It listens to all IP - MAC associations on the local network and detects any anomalies. If a MAC address is associated with two or more IP addresses, it displays a warning and records this information.

These modules were developed using the Scapy library in Python, which offers great flexibility for manipulating network packets. They allow for targeted MITM attacks, network traffic listening, and detection of potential ongoing attacks.

## Usage

We conducted MITM attack experiments using our `mitm` package and present some screenshots here to illustrate these experiments. 

### Using the atk.py module for ARP attack
[atk](/images/atk1.png)
This screenshot presents the usege of the `atk.py` module to conduct an ARP poisoning attack. You can see that the parameters are the IP addresses of the client and server.

### Capturing HTTP traffic with the listen.py module
[http](/images/http.png)
In this screenshot, we demonstrate the use of the `listen.py` module to capture HTTP traffic between the client and the server. You can observe the HTTP requests and responses that are intercepted and displayed by the module.

### Capturing DNS requests with the listen.py module
[dns](/images/dns.png)
This screenshot presents the use of the `listen.py` module to capture DNS requests made by the client. You can observe the DNS requests that are intercepted and displayed by the module.

### Detecting an ARP attack with the detect.py module
[detect](/images/detect.png)
This screenshot presents the use of the `detect.py` module to detect an ARP poisoning attack. You can see the warning displayed by the module, indicating that a MAC address is associated with multiple IP addresses.

### Using the atk.py module for DHCP attack
[atk2](/images/atk2.png)
In this screenshot, we illustrate the use of the `atk.py` module to conduct a DHCP-based MITM attack. You can see the command used to forge the falsified DHCP responses, which will be sent to the client. These responses contain false network configuration information, including a fake default router.
