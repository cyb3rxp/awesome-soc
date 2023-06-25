# [EN] useful command lines for incident response Cheat sheet 
# [FR] Memento de lignes de commande utiles en réponse à incident

# Linux 

## [EN] Find IP address within log lines, using GREP (or any REGEX compatible tool)
## [FR] Trouver des adresses IP dans des lignes de journaux, en utilisant Grep (ou un autre outil compatible REGEX) :

### [FR] Recherche dans les fichiers journaux .log texte dans /var/log/ :
### [EN] Search within plaintext log files, in /var/log/:
grep -ohE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' /var/log/*.log* |sort -n -k 1 |uniq -c |sort -n

### [FR] Recherche dans les fichiers journaux compressés:
### [EN] Search within compressed log files:
zgrep -ohE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' /var/log/*.log* |sort -n -k 1 |uniq -c |sort -n
