from scapy.all import sniff, ARP
from datetime import datetime
from json import dumps
from scapy.interfaces import get_if_list

# Liste de tous les associations detectées
assoc_mac_ip = {}
# Liste des associations irregulaires
assoc_irregulaires = []

def arp():
    '''Capturer les requêtes ARP, afficher et sauvegarder les associations anormalles'''
    print("..\n[Ecoutant]\n..")
    # Capture que les trames ARP
    sniff(
        lfilter=lambda t: ARP in t,
        iface=get_if_list(),
        prn=detecter
        )
    

def detecter(trame):
    '''Surveiller chaque requête ARP'''
    ip_src2 = trame[ARP].psrc
    mac_src = trame[ARP].hwsrc

    if mac_src in assoc_mac_ip:
        ip_src1 = assoc_mac_ip[mac_src]

        if ip_src1 != ip_src2:
            now = str(datetime.now()).split('.')[0]
            assoc = {'date':now, 'mac':mac_src, 'ip':[ip_src1,ip_src2]}
            flag = True
            for pos in assoc_irregulaires:
                if ip_src1 in pos['ip'] and ip_src2 in pos['ip']:
                    flag = False
                    break
            if flag:
                # Sauvegarder les associations anormalles
                print(assoc)
                assoc_irregulaires.append(assoc)
                with open('assoc_irregulaires.json','w') as file:
                    file.write(dumps(assoc_irregulaires))
    else:
        assoc_mac_ip[mac_src] = ip_src2
