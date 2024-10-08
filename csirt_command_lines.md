# [EN] Command lines for incident response cheat sheet // [FR] Memento de lignes de commande utiles en réponse à incident

# Linux 

## [EN] Find IP address within log lines, using GREP (or any REGEX compatible tool) // [FR] Trouver des adresses IP dans des lignes de journaux, en utilisant Grep (ou un autre outil compatible REGEX) :

### [EN] Search IP addresses within plaintext log files // [FR] Recherche d'adresses IP dans les fichiers journaux .log texte dans /var/log/ :
 > grep -ohE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' /var/log/\*.log\* |sort -n -k 1 |uniq -c |sort -n

### [EN] Search IP addresses within compressed log files // [FR] Recherche d'adresses IP dans les fichiers journaux compressés :
> zgrep -ohE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' /var/log/\*.log\* |sort -n -k 1 |uniq -c |sort -n

### [EN] Count number of unique IP addresses that were blocked using Fail2Ban // [FR] Compter le nombre d'adresses IP uniques qui ont été bloquées par Fail2Ban :
> zgrep "Ban " /var/log/fail2ban.log* | grep -v "Restore Ban"  |  zgrep -ohE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])'   |sort -n -k 1 |uniq -c |wc -l

### [EN] List active services (Systems with SystemD) // [FR] Lister les services (systèmes avec SystemD) :
> systemctl list-units --type=service --state=active

### [EN] List all TCP/UDP sockets // [FR] Lister toutes les sockets TCP/UDP ouvertes :
> netstat -laputenv

### [EN] List all TCP/UDP sockets with "established" state // [FR] Lister toutes les sockets TCP/UDP avec status "établi" :
> netstat -laputenv | grep ESTABLISHED


# Sysmon

## [EN] Command line to run Zircolite from Docker on Windows, have it analyse Sysmon XML file, and generate a report in a shared folder // [FR] Ligne de commande pour exécuter Zircolite depuis un Docker Windows, afin d'analyser un journal XML Sysmon et générer un rapport dans un dossier partagé 

> docker run -it -v c:\docker\zircolite\:/mnt/disk_Win wagga40/zircolite:latest     --evtx data/sysmon.evtx     -o /mnt/disk_win/case/detected_events.json    --template templates/exportForZircoGui.tmpl --templateOutput /mnt/disk_win/case/data.js
