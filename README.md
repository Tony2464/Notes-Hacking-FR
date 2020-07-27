# Notes test d'intrusion et hacking

Notes pour du test d'intrusion et tout lien avec la sécurité informatique dans son ensemble

Anthony Fargette

## Table des matières

- [Notes test d'intrusion et hacking](#notes-test-dintrusion-et-hacking)
  - [Table des matières](#table-des-matières)
  - [Abréviations](#abréviations)
  - [Quelques commandes utiles](#quelques-commandes-utiles)
    - [Interfaces réseau](#interfaces-réseau)
  - [4 Phases de pénétration](#4-phases-de-pénétration)
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
    - [4 étapes de scan](#4-étapes-de-scan)
    - [Liste de numéros de ports et services associés communs](#liste-de-numéros-de-ports-et-services-associés-communs)
    - [Ping](#ping)
    - [Fping](#fping)
    - [Scan des ports](#scan-des-ports)
      - [Connexion en 3 étapes](#connexion-en-3-étapes)
      - [Scan TCP Connect avec Nmap](#scan-tcp-connect-avec-nmap)
      - [Scan UDP avec nmap](#scan-udp-avec-nmap)
      - [Scan Xmas](#scan-xmas)
      - [Scan Null](#scan-null)
      - [NSE (Nmap Scripting Engine)](#nse-nmap-scripting-engine)
      - [Options supplémentaires](#options-supplémentaires)
    - [Connexion à distance](#connexion-à-distance)
    - [Scan de vulnérabilités avec Nessus](#scan-de-vulnérabilités-avec-nessus)
  - [3. Exploitation](#3-exploitation)
    - [Medusa](#medusa)
    - [Metasploit](#metasploit)
    - [Meterpreter](#meterpreter)
    - [John The Ripper](#john-the-ripper)
      - [Craquage des mots de passe en local](#craquage-des-mots-de-passe-en-local)
        - [SamDump2](#samdump2)
        - [BkHive](#bkhive)
        - [John](#john)
      - [Craquage à distance](#craquage-à-distance)
      - [Craquage des mots de passe UNIX/Linux et élévation des privilèges](#craquage-des-mots-de-passe-unixlinux-et-élévation-des-privilèges)
    - [Réinitialisation de mots de passe sur machine Windows avec chntpw](#réinitialisation-de-mots-de-passe-sur-machine-windows-avec-chntpw)
    - [Wireshark](#wireshark)
      - [Macof](#macof)
    - [Armitage](#armitage)
    - [SET (Social Engineering Toolkit)](#set-social-engineering-toolkit)
      - [Menu SET](#menu-set)
    - [Exploitation Web](#exploitation-web)
  - [4. Postexploitation et maintien de l'accès](#4-postexploitation-et-maintien-de-laccès)

## Abréviations

@IP = adresse IP

## Quelques commandes utiles

### Interfaces réseau

Énumérer toutes interfaces :  
`ifconfig -a`

Activer / désactiver une carte réseau :

`ifconfig eth0 up/down`

Mettre une @IP sur une carte réseau :
`ifconfig eth0 up @IP`

Retirer la configuration dhcp :
`dhclient -r`

Demander la configuration dhcp :
`dhclient`

## 4 Phases de pénétration

1. [Reconnaissance](#1-reconnaissance)
2. [Scan](#3-exploitation)
3. [Exploitation](#3-exploitation)
4. [Postexploitation et maintien de l’accès](#4-postexploitation-et-maintien-de-lacc%c3%a8s)

**PTES** *(Penetration Testing Execution Standard)*

**OSINT** *(Open Source Intelligence)*

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

cache: *Cherche dans les caches du moteur de recherche*

filetype: *Cherche par type de fichier*

Possibilité de combiner les attributs

[GHDB (Google Hacking Database)](https://www.exploit-db.com/google-hacking-database)

Recommander d'utiliser les autres moteurs de recherche.

### TheHarvester

Recherches d’adresses de messagerie, de sous-domaine et hotes appartenant à un nom de domaine.

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

Récupérer des métadonnées sur internet à partir d’un nom de domaine :

`metagoofil`

-d *domaine*
-t *type de fichier*
-l *limite de recherche*
-n *limte de fichiers à telecharger*
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
4. Scanner le système à la recherche de vulnérabilités avec Nessus

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

paquet ICMP, envoie d’une requête ICMP Echo.
`ping @IP`

icmp_seq *ordre du paquet*
ttl *durée de vie du paquet, nombre de saut que peut effectuer le paquet avant expiration*
time *duree total du parcours du paquet vers et depuis la cible*

### Fping

Balayage de ping dans une plage d'@IP

`fping -a -g @IPdebut @IPfin > ipList.txt`

-a *inclure uniquement les machines actives*

-g *definition d'une plage d'@IP*

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

Un scan SYN ("Stealth Scan") n'effectue que les 2 étapes puis renvoie un RST (réinitialisation) qui indique à la cible d'oublier les paquets precedents et de fermer la connexion.

#### Scan UDP avec nmap

Scan plutot lent.

`nmap -sU @IP`

-sU *Scan UDP*
-sV *Scan avec version*

#### Scan Xmas

Appelé ainsi car il envoie un paquet contenant de nombreux drapeaux (FIN, PSH et URG).

Si l'OS respecte les normes RFC **(Request For Comments)**, et que un port recoit un paquet dans lequel le drapeau SYN, ACK ou RST n'est pas positionné (type de paquet Xmas) alors il doit répondre par un paquet RST.

`nmap -sX -p- -Pn @IP`

-X *Scan Xmas*

#### Scan Null

`nmap -sN -p- -Pn @IP`

-sN *Scan Null*

Comme un scan Xmas, il ne respecte pas les communications TCP normales cependant il est tout de meme different car il ne contient aucun drapeau.
Seuls les ports fermés et qui respectent le RFC répondront.

Les avantages de ces 2 scans sont que dans certains cas, il est possible de contourner les filtres simples ACL **(Acess Control List)**. L'idée est de bloquer les paquets SYN entrants.

Les scans Xmas et Null determinent seulement si les ports sont ouverts ou fermés.

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

-T *Modifie la rapidité de scan des ports 0-5 , 0 lent au plus rapide 5 mais moins preciss*

-O *Détermine l'OS de la cible*

### Connexion à distance

Tentative de connexion avec les services Telnet et SSH.

`telnet @IP`
`ssh root@@IP`

### Scan de vulnérabilités avec Nessus

Téléchargement depuis le site pour obtenir un paquet deb.
Installation avek dpkg (gestionnaire de paquet debian):
`dpkg -i nom_de_paquet.deb`

Une fois installé, il faut lancer le serveur Nessus :
`/etc/init.d/nessusd start`

Acces au service via le navigateur web en https et le port 8834 :
`https://localhost:8834`

Sélectionner son offre (Essentials).
Obtenir pour rentrer le code d'activation.

Entrer le nom d'utilisateur et son mot de passe pour la connexion en local.
Nessus va alors télécharger tous les autres composants nécessaires.

Dans *Setting* > *Advanced Settings* > *Scanning* verifier que le *Safe Checks* est à Yes car sans cela le scan pourrait provoquer un disfonctionnement du réseau et du système.
Lancement d'un scan avec le bouton *New Scan*, choisir le type de scan adéquat.

OpenVAS est une version fork de Nessus en open-source.

## 3. Exploitation

Contrôle sur un système.
Partie précédente : [2. Scan](#2-scan)
Partie suivante : [4. Exploitation](#4-postexploitation-et-maintien-de-lacc%c3%a8s)

### Medusa

Système parallèle d'ouverture de session par brute force qui tente d'accéder à des services d'authentification à distance.
Connaitre l'@IP, le service, avoir des noms d'utilisateurs potentiels et une wordlist de mots de passe.

Wordlist déjà fournis avec Kali :
`/usr/share/wordlists`
`/usr/share/john/password.lst`

Commande Medusa :
`medusa -h @IP -u nom_utilisateur -P wordlist -M service`

-h *@IP de l'hôte*
-u *nom de l'utilisateur*
-U *fichier contenant une liste d'utilisateurs à passer*
-p *un seul mot de passe*
-P *fichier contenant une liste de mots de passe à passer*
-M *nom du service*

Autres logiciels : Hydra, ...

### Metasploit

Metasploit Framework permet de sélectionner la cible et sélectionner les charges *(payload)* à effectuer.
Exploite les systèmes scannés.
Exploitation en CLI avec Msfconsole :
`msfconsole`

Mettre à jour MetasploitF :
`msfupdate`
*Inutil dans Kali.*

Rechercher l'exploit :
`search nom_exploit`
*Possibilité de rechercher par date, entrer la date apres search*

Utiliser l'exploit :
`use nom_exploit`

Examiner les charges disponibles :
`show payloads`

Sélectionner le payload :
`set payload nom_payload`

Connaître les options disponibles de la charge :
`show options`

Configurations des hôtes distants *(Remote)* et locals *(Local)* :
`set RHOST @IP_distante`
`set LHOST @IP_locale`

Démarrer l'exploit :
`exploit`

Partie précédente : [2. Scan](#2-scan)
Partie suivante : [4. Postexploitation et maintien de l'accès](#4-postexploitation-et-maintien-de-lacc%c3%a8s)

Exemples de charges *(payloads)* à envoyer sur les machines Windows :

- windows/adduser *crée sur la machine cible un nouvel utilisateur appartenant au groupe administrateur*
- windows/exec *Exécute sur la machine cible un binaire (.exe)*
- windows/shell_bind_tcp *Ouvre sur la machine cible un shell de commande et attend une connexion*
- windows/shell_reverse_tcp *La machine cible se connecte à l'assaillant et ouvre un shell de commande*
- windows/meterpreter/bind_tcp *Installe Meterpreter sur la machine cible et attend une connexion*
- windows/meterpetrer/reverse_tcp *Installe Meterpreter sur la machine cible et crée une connexion de retour à l'assaillant*
- windows/vncinjetc/bind_tcp *Installe VNC sur la machine cible et attend une connexion*
- windows/vncinjetc/reverse_tcp *Installe VNC sur la machine cible et renvoie une connexion VNC à la cible*

### Meterpreter

Charge de Matasploit qui donne à l'assaillant un shell de commande pour interagir avec la machine cible.

Avantages :

- s'exécute en mémoire
- pas d'utilisation du disque
- discret
- difficile à détecter
- s'exécute avec les droits associés au programme qui a été exploité
- ne lance pas de nouveaux processus

Commandes utiles :

- `migrate` : déplace le serveur vers un autre processus.
- `cat` : afficher le contenu d'un fichier.
- `download` : télécharger une copie d'un fichier ou répértoire de la machine cible.
- `upload` : transférer des fichiers vers la machine cible.
- `edit` : éditer un fichier.
- `execute` : éxecuter une commande.
- `kill` :  terminer un processus.

### John The Ripper

Craquage de mots de passe pour augmenter les privilèges.

1. Localiser le fichier des mots de passe chiffrés sur le système et le télécharger.
2. Employer un outil pour convertir les mots de passe chiffrés en mots de passe en clair.

Tester la config avec john :
`john --test`

#### Craquage des mots de passe en local

Sur Windows, le fichier de mots de passe se nomme SAM *(Security Account MAnager)*
Présent dans le dossier **C:\Windows\System32\Config\\**
Cependant Windows bloque l'acces à ce fichier, il faut donc booter sur un autre OS pour contourner ce verrouillage.

Une fois booté sur un autre OS, il faut monter le disque local de la machine :
`fdisk -l` *Pour lister les disques présents*
`mkdir /mnt/sda1` *Créer un point de montage*
`mount dev/sda1 /mnt/sda1` *Monter le disque cible*

Rechercher le fichier SAM :
`cd /mnt/sda1/Windows/System32/config`

##### SamDump2

Déchiffrer le fichier SAM avec SamDump2 qui se sert d'un fichier system *(situé à côté du fichier SAM normalement)* sur la machine locale pour déchiffrer :
`samdump2 SAM system > /tmp/mdp_chiffres.txt`

Vérifier que les mots de passe ont bien été copiés :
`cat /tmp/mdp_chiffres.txt`

##### BkHive

Sur certains systèmes Windows l'accès aux mots de passe chiffrés peut nécissiter une étape supplémentaire.
BkHive sert à extraire la clef syskey à partir de la ruche système.

`bkhive system cle_sys.txt`
`samdump2 SAM cle_sys.txt > /tmp/mdp_chiffres.txt`

##### John

Craquer le fichier contenant les mots de passe chiffrés :
`john /tmp/mdp_chiffres.txt`

#### Craquage à distance

Avec une session Meterpreter, une commande permet de contourner les mécanismes de sécurité de Windows et d'obtenir la liste des mots de passe hashés :
`hasdump`

Il suffit plus qu'à copier cette liste affichée à l'écran.

#### Craquage des mots de passe UNIX/Linux et élévation des privilèges

Le fichier contenant les mots de passe chiffrés est situé dans :
`/etc/shadow`
Il faut cependant avoir un niveau de privilège suffisant pour y accéder.
Pour contrer ce problème, nous pouvons les obtenir en combinant les fichiers *passwd* et *shadow*:
`unshadow /etc/passwd /etc/shadow > /tmp/linux_mdp_chiffres.txt`

### Réinitialisation de mots de passe sur machine Windows avec chntpw

Nécessite un accès physique de la machine cible.
Objectif : écraser le fichier SAM et créer un nouveau mot de passe vide pour n'importe quel utilisateur.
Booter sur un autre OS et monter la partition de la machine.
Commande :
`chntpw -i /mnt/sda1/Windows/System32/config/SAM`

Choisir *Edit user data and passwords*
-i *mode interactif*

### Wireshark

La plupart des cartes réseau opèrent en mode non-promiscuité. Cela signifie que l'interface réseau de la carte NIC *(Network Interface Card)* ne transmet que le trafic qui lui est déstiné sinon elle ne transmet pas.
En mode promiscuité, la carte réseau accepte tous les paquets entrants.

Un concentrateur *(hub)* fonctionne en transmettant tout le traffic à tous les appareils connectés à ses ports.
Un commutateur *(switch)* fonctionne en transmettant uniquement le traffic destiné au port en comparant avec l'adresse MAC et le numéro de port pré-enregistrés de la carte réseau.

#### Macof

Cependant un commutateur peut se transformer en concentrateur.
Un commutateur a une mémoire limitée pour la table d'addressage MAC.
En épuisant cette mémoire d'adresses MAC, il se retrouvera incapable d'effectuer le travail de transférer les paquets au bon port, il diffusera alors le traffic à tous les ports : c'est le *fail open*. Il agira alors comme un simple concentrateur.

Dans le cas inverse, un commutateur configuré en mode "fermé" va arrêter de transférer tous les paquets : c'est le *fail closed*. Dans cette situation l'attanquant va pouvoir provoquer un déni de service du commutateur et bloquer une partie du réseau.

Macof de la suite Dsniff est un outil qui va permettre d'inonder le commutateur avec des centaines d'adresses MAC aléatoires. Si le commutateur est configuré en mode fail open en cas de défaillance, il va se comporter comme un concentrateur et diffuser le trafic vers tous les ports ce qui permettra d'analyser l'ensemble du traffic.

`macof -i eth0 -s 192.168.56.101 -d @IP_commutateur`

-i *précise la carte réseau*
-s *@IP source*
-d *@IP destination*

Lancer Wireshark avec les privilèges pour qu'il ait accès à la configuration des cartes réseau :
`sudo wireshark`

Séléctionner une carte réseau et commencer à capturer le traffic avec les options par défaut.
Si les inforamtions ne sont pas chiffrées, on peut alors les voir en clair.

### Armitage

Armitage est une version de Metasploit Framework avec une interface graphique.
Vant de lancer Armitage il faut démarrer les services postgresql et metasploit :
`service postgresql start`
`service metasploit start`

Nous pouvons alors lancer Armitage :
`sudo armitage`
Il affiche alors une boîte de dialogue pour se connecter, laisser les paramètres par défaut et cliquer sur Connect.
Il demande ensuite de si nous voulons démarrer Metasploit. Cliquer sur Oui.

Identification des cibles potentielles :
Séléctionner Hosts, Nmap Scan, Quick Scan (OS detect).
Entrer l'@ IP ou la plage d'@ IP à scanner.
Exemple :
`192.168.1.1-255`
Les cibles potentielles sont ensuite affichées à l'écran.

Nous pouvons effectuer une attaque Hail Mary qui va lancer une vague automatique d'exploits contre la cible sans discretion. Il va mettre en relation les ports découverts par Nmap avec les exploits disponibles de Metasploit. Si la machine est compromise, elle sera affichée avec des éclairs autours.
Nous pouvons alors consulter la liste des Shell obtenus sur la machine cible en effectuant un clique droit > Shell > Interact.

### SET (Social Engineering Toolkit)

Outil permettant permettant diverses attaques basées sur l'hameçonnage.
Lancer SET :
`sudo setoolkit`

#### Menu SET

Dans cette catégories nous retrouvons :

**1. Spear-Phishing Attack Vectors**
Envoi massif de courriels spécifiques avec des pièces jointes malveillantes vers une personne ou un groupe de personnes.
**2. Website Attack Vectors**
Conception de faux sites ressemblant aux vraix dans le but de tromper un utilisateur pour qu'il clique sur un lien malveillant.
**3. Infectious Media Generator**
Création d'une backdoor metasploit dans une clé USB ou dans un DVD avec à l'intérieur un autorun.inf qui compromettra le système sur lequel il est connecté.
**4. Create a Payload and Listener**
Création d'un virus basé sur metasploit. Le keylogger se présente comme un fichier .exe exportable et exécutable sur la machine cible.
**5. Mass Mailer Attack**
Phishing de masse avec une liste d'emails. Possibilité d'envoyer par une adresse email spécifiée.
**6. Arduino-Based Attack Vector**
USB HID Attack pour micro-controlleur type [Arduino](https://www.arduino.cc/).
**7. Wireless Access Point Attack Vector**
Cration de point d'acces et DNS Spoofing pour rediriger la victime connectée à notre point d'accès vers de faux sites internet.
**8. QRCode Generator Attack Vector**
Creation de QRCode contenant un lien malveillant
**9. Powershell Attack Vectors**
Injection de codes malveillants et attaques via PowerShell
**10. Third Party Modules**
Ajout de nos propore modules

### Exploitation Web

Exemples de framworks pour pour le hacking des aplicaitons web : w3af, Burp Suite, ZAP (Zed Attack Proxy), Websecurify, Paros, ...

## 4. Postexploitation et maintien de l'accès
