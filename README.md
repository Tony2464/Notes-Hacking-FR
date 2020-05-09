# Notes pour du test d'intrusion Anthony Fargette 2020 

## Table des matières

- [Notes pour du test d'intrusion Anthony Fargette 2020](#notes-pour-du-test-dintrusion-anthony-fargette-2020)
  - [Table des matières](#table-des-mati%c3%a8res)
  - [Abréviations](#abr%c3%a9viations)
  - [Quelques commandes utiles](#quelques-commandes-utiles)
    - [Interfaces réseau](#interfaces-r%c3%a9seau)
  - [4 Phases de pénétration](#4-phases-de-p%c3%a9n%c3%a9tration)
  - [1. Reconnaissance](#1-reconnaissance)
    - [Httrack](#httrack)
    - [Google Hacking](#google-hacking)
    - [TheHarvester](#theharvester)
    - [Whois](#whois)
    - [Host](#host)
    - [Nslookup](#nslookup)
    - [Dig](#dig)
    - [Fierce](#fierce)
    - [Metagoofil](#metagoofil)
    - [ThreatAgent](#threatagent)
  - [2. Scan](#2-scan)
    - [4 étapes de scan](#4-%c3%a9tapes-de-scan)
    - [Liste de numéros de ports et services associés communs](#liste-de-num%c3%a9ros-de-ports-et-services-associ%c3%a9s-communs)
    - [Ping](#ping)
    - [Fping](#fping)
    - [Scan des ports](#scan-des-ports)
      - [Connexion en 3 étapes](#connexion-en-3-%c3%a9tapes)
      - [Scan TCP Connect avec Nmap](#scan-tcp-connect-avec-nmap)
      - [Scan UDP avec nmap](#scan-udp-avec-nmap)
      - [Scan Xmas](#scan-xmas)
      - [Scan Null](#scan-null)
      - [NSE (Nmap Scripting Engine)](#nse-nmap-scripting-engine)
      - [Options supplémentaires](#options-suppl%c3%a9mentaires)
  - [3. Exploitation](#3-exploitation)

## Abréviations

@IP = adresse IP

## Quelques commandes utiles

### Interfaces réseau

Énumérer toutes interfaces :
`ifconfig -a`

Activer / désactiver une carte réseau :
`ifconfig eth0 up/down`

Mettre une @IP sur un carte réseau :
`ifconfig eth0 up @IP`

Retirer la configuration dhcp :
`dhclient -r`

Demander la configuration dhcp :
`dhclient`

## 4 Phases de pénétration

1. [Reconnaissance](#reconnaissance)
2. [Scan](#scan)
3. Exploitation
4. Postexploitation et maintien de l’accès

**PTES** *(Penetration Pesting Execution Standard)*

**OSINT** *(Open Source Intellgence)*

## 1. Reconnaissance

Recueil d’informations.
Bien noter toutes les informations reccueillies.
Association d’informations collectees en @IP

Partie suivante : [2. Scan](#2-scan)

### Httrack

Récupérer le contenu d'un site web en mode interactif :
`httrack`

En CLI :
`httrack http://url -O /repertoire`

### Google Hacking

Google hacking ou Google Dork
Recherches avancées avec Google
Exemples de recherches avec des attributs :
`site:url nom_de_la_recherche`

Autre attributs :
intitle: *Cherche les sites dont le titre contient le mot recherche*
inurl: *Cherche les sites dont l'url contient le mot recherche*
cache: *Cherche dans les chaches du moteur de recherche*
filetype: *Cherche par type de fichier*

Possibilité de combiner les attributs

[GHDB (Google Hacking Database)](https://www.exploit-db.com/google-hacking-database)

Recommander d'utiliser les autres moteurs de recherche.

### TheHarvester

Recherches d’adresses de messagerie, de sous-domaine et hotes appartenant a un nom de domaine.

`theHarvester -d nom_de_domaine -l 10 -b google`

-d *domaine*
-l *limite*
-b *répertoire public de recherche*
-b all *pour utiliser tous les repertoires*

### Whois

Obtenir des infos à partir d’un nom de domaine.

`whois nom_de_domaine`

Site web pour recueillir les informations :
[What’s that site running netcraft](https://sitereport.netcraft.com/)

### Host

Traduire les noms de domaine en @IP :
`host nom_de_domaine`

Lister les recherches :
`host -a nom_de_domaine`

### Nslookup

Obtenir les informations du serveur DNS mode interactif :
`nslookup`
`server @IPserver`
`set type=any`
`.`

### Dig

Tenter un transfert de zone sur un serveur DNS :
`dig @IP_serveur_dns nom_de_domaine -t AXFR`

### Fierce

Sacnner DNS et enumerer les @IP actifs du nom de domaine :

`fierce -dns nom_de_domaine`

### Metagoofil

Récupérer des métadonnées sur internet a partir d’un nom de domaine :

`metagoofil`

-d *domaine*
-t *type de fichier*
-l *limite de recherche*
-n *limte de fichiers a telecharger*
-o *dossier de sortie*
-f *fichier ou enregistrer les liens html*

`metagoofil -d kali.org -t pdf -l 100 -n 25 -o kalipdf -f kalipdf.html`

### ThreatAgent

Site web qui recherche toutes les informations avec un nom de domaine.
Nécessite un compte pour l’utiliser

Logiciel de recherches d’infos sous windows : FOCA, Search Diggity, Maltego, RobTex

## 2. Scan

Association d’adresses IP à des ports ou services ouverts.
Partie précédente : [1. Reconnaissance](#1-reconnaissance)
Partie suivante : [3. Exploitation](#3-exploitation)

### 4 étapes de scan

1. Déterminer si un système est actif avec des paquets ping
2. Scanner le ports du système avec Nmap
3. Utiliser le moteur de scripts Nmap (NSE, Nmap Scripting Engine) pour examiner de façon plus précise la cible
4. Scanner le système a la recherche de vulnérabilités avec Nessus

### Liste de numéros de ports et services associés communs

| Numéro de port | Description                              |
| -------------- | ---------------------------------------- |
| 20             | Transfert de données FTP                 |
| 21             | Contrôle FTP                             |
| 22             | SSH                                      |
| 23             | Telnet                                   |
| 25             | SMTP (messaegrie electronique)           |
| 53             | DNS                                      |
| 80             | HTTP                                     |
| 137-139        | NetBIOS                                  |
| 443            | HTTPS                                    |
| 445            | SMB (partage de ressources sous Windows) |
| 1433           | MSSQL (Microsoft SQL)                    |
| 3306           | MySQL                                    |
| 3389           | RDP                                      |
| 5800           | VNC au-dessus de HTTP                    |
| 5900           | VNC                                      |

### Ping

paquet ICMP, envopie d’une requete ICMP Echo.
`ping @IP`

icmp_seq *ordre du paquet*
ttl *durée de vie du paquet, nombre de saut que peut effectuer le paquet avant expiration*
time *duree total du parcours du paquet vers et depuis la cible*

### Fping

Balayage de ping dans une plage d'@IP

`fping -a -g @IPdebut @IPfin > ipList.txt`

-a *inclure uniquement les machines actives*
-g *definiation d'un plage d'@IP*

### Scan des ports

Nombre total de ports d'un ordinateur : **65 536 (0 - 65 535)**
Réponse aux protocoles TCP **(Transmission Control Protocol)** ou UDP **(User Datagram Protocol)** selon les services mis en place.

Services utilisant l'UDP : DHCP, DNS, SNMP, TFTP ...

#### Connexion en 3 étapes

Lors d'une communication entre 2 machines avec le protocole TCP, elles utilisent une connexion en 3 étapes **(Three-way handshake)**

Le premier ordinateur se connecte au second en envoyant un paquet SYN à un numéro de port precisé. Si le second est à l'écoute, il répond par un paquet SYN/ACK. Si le premier le recoit, il repond alors par un paquet ACK. Les 2 ordinateurs peuvent enfin communiquer.

#### Scan TCP Connect avec Nmap

Scan de port.

`nmap -sT -p- -Pn @IP`
`nmap -sT -p- -Pn @IPdebut-@IPfin_dernier_octet`

-s *Précision du type de scan à effectuer, par defaut scan SYN*
-sT *Scan TCP Connect*
-sS *Scan SYN*
-p- *Scan de tous les ports à la place des 1000 par défaut*
-P *Saute l'etape de decouverte*
-n *Scan des machines en les considérant comme actives*
-iL ipList.txt *spécifie un fichier contenant une liste des @IP à scanner*

Un scan SYN ("Stealth Scan") m'effectue que les 2 étapes puis renvoie un RST (réinitialisation) qui indique a la cible d'oublier les paquets precedents et de fermer la connexion.

#### Scan UDP avec nmap

Scan plutot lent.

`nmap -sU @IP`

-sU *Scan UDP*
-sV *Scan avec version*

#### Scan Xmas

Appelé ainsi car il envoie un paquet contenant de nombreux drapeaux (FIN, PSH et URG).

Si l'OS respecte les normes RFC **(Request For Comments)**, et que un port recoit un paquet danslequel le drapeau SYN, ACK ou RST n'est pas positionné (type de paquet Xmas) alors il doit répondre par un paquet RST.

`nmap -sX -p- -Pn @IP`

-X *Scan Xmas*

#### Scan Null

`nmap -sN -p- -Pn @IP`

-sN *Scan Null*

Comme un scan Xmas, il ne respecte pas les communication TCP normales cependant il est tout de meme different car il ne contient aucun drapeaux.
Seuls les ports fermes et qui respectent le RFC répondront.

Les avantages de ces 2 scans sont que dans certains cas, il est possible de contourner les filtres simple ACL **(Acess Control List)**. L'idée est de bloquer les paquets SYN entrants.

Les scans Xmas et Null determinent seulement si les ports sont ouverts ou fermés

#### NSE (Nmap Scripting Engine)

Permet d'étendre les fonctionnalités de Nmap.
Différentes catégories :

- auth
- banner *Crée une connexion sur un port TCP et affiche toute sortie, utile pour identifier des services méconnus attachés à un port inhabituel*
- broadcast
- brute
- default
- discovery
- dos
- exploit
- external
- fuzzer
- intrusive
- malware
- safe
- version
- vuln *Recherche des problèmes connus sur l'OS*

`nmap --script banner @IP`

#### Options supplémentaires

## 3. Exploitation
