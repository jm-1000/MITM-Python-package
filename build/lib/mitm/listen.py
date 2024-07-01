from scapy.all import sniff, IP, DNS
from scapy.layers.http import HTTPRequest as httpreq
from datetime import datetime
from .atk import det_iface
import json, sqlite3, copy


liste_req = []
dernier_rqt={"ip": "", "methode":"", "URI":""}

def http(ip, nb):
    '''Capturer les requêtes HTTP issues de ip pendant nb secondes et afficher des paramètres HTTP'''
    # Déterminer l'interface à utiliser
    interface = det_iface(ip)

    info = "..\n[info] Les requêtes http vont être écouter sur l'interface " 
    info += interface +" pendant "+ str(nb) +" secondes!\n..\n[Ecoutant]\n.."
    print(info)

    # Charger la sauvegarde sur le fichier json
    try:
        with open('capture.json') as file:
            global liste_req
            liste_req = json.loads(file.read())
    except: print('..\n[erreur] Impossible de charger la sauvegarde!')

    # Capturer les paquets en provenance de l'hôte 'ip'
    sniff(
        lfilter=lambda p:IP in p and p[IP].src == ip,
        prn=affichage_http,
        timeout=nb,
        iface=interface
        )


def affichage_http(paquet):
    '''Afficher des paramètres http'''
    if httpreq in paquet:
        req = paquet[httpreq]
        requete = {
                'ip':req.Host.decode("utf-8"),
                'methode':req.Method.decode("utf-8"), 
                'URI':req.Path.decode("utf-8")
                }
        global dernier_rqt
        if requete != dernier_rqt:
            # Faire la copie de la valeur de la variable
            dernier_rqt = copy.copy(requete)

            requete['date'] = str(datetime.now())
            print(
                requete['date'],
                requete['ip'],
                requete['methode'],
                requete['URI'],
                "\n..",
                sep='; ') 
            # Sauveguarder les requêtes sur un fichier json
            liste_req.append(requete)
            with open('capture.json','w') as file:
                file.write(json.dumps(liste_req)) 
            
            try:
                sauvegarde_sql(requete)
            except: print('..\n[erreur] Impossible de faire la sauvegarde!')

        

def sauvegarde_sql(requete):
    '''Sauvegarder la requête sur le database'''
    connexion = sqlite3.connect("capture.db")
    cursor = connexion.cursor()
    req_sql = "select * from sqlite_master"

    if cursor.execute(req_sql).fetchall() == []:
        # Si le database est vide, on crée la table httpreq
        req_sql = '''create table httpreq (
            date varchar(100) primary key,
            ip varchar(15),
            methode varchar(10),
            uri varchar(500)
        )'''
        cursor.execute(req_sql)
        connexion.commit()

    req_sql = f'''
            insert into httpreq values (
                "{requete['date']}",
                "{requete['ip']}",
                "{requete['methode']}",
                "{requete['URI']}")
            '''
    cursor.execute(req_sql)
    connexion.commit()
    connexion.close()



def dns(ip, nb):
    '''Capturer les requêtes DNS pendant nb secondes et afficher l'hôte demandé par le ip'''
    # Déterminer l'interface à utiliser
    interface = det_iface(ip)

    info = "..\n[info] Les requêtes DNS vont être écouter sur l'interface " 
    info += interface +" pendant "+ str(nb) +" secondes!\n..\n[Ecoutant]\n.."
    print(info)
    # Capturer les paquets en provenance de l'hôte 'ip'
    sniff(
        # Filtrer que les requêtes DNS
        lfilter=lambda p: IP in p and p[IP].src == ip and DNS in p,
        # Afficher l'hôte demandée
        prn=lambda p: print(p[DNS].qd.qname.decode('utf-8')),
        timeout=nb,
        iface=interface
        )

