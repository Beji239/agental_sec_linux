# core/detection_plain.py
# Plain-English descriptions of every rule, for the Detections page.
# The precise wording stays in core/detections.py, which the agent reads.
# One or two short sentences each, no jargon where a common word will do.

PLAIN = {
    # Packet capture
    "PKT-1001": "One device sent or received a lot of traffic for a sustained "
                "period. Often a backup or a big download, worth a glance if "
                "you do not recognise it.",
    "PKT-1002": "A device keeps contacting the same place on a regular timer. "
                "Malware phones home like this, but so do update checkers.",
    "PKT-1003": "Traffic came in faster than the app could record it, so some "
                "of it was missed. A quiet period here may not really be quiet.",
    "PKT-1010": "Network traffic contained the fingerprint of a well-known "
                "hacking toolkit. Treat as serious until explained.",
    "PKT-1011": "Someone sent text that tries to trick a database (SQL "
                "injection) to a service on your network.",
    "PKT-1012": "Someone sent text that tries to inject a script into a web "
                "page (cross-site scripting) to a service on your network.",
    "PKT-1013": "Something from outside tried to reach a port on this machine "
                "that should not be open to it.",
    "PKT-1014": "This machine connected out to a port on the internet that "
                "attackers commonly use to control infected machines.",
    "PKT-1015": "This machine connected out on an unusual port. Not "
                "necessarily bad, worth checking which program did it.",
    "PKT-1016": "A message telling this machine to change how it routes "
                "traffic came from outside your network. That should not "
                "happen.",
    "PKT-1017": "A routing message arrived with a garbled sender address. "
                "Usually a bug in some device rather than an attack.",
    "PKT-1099": "Traffic was flagged as a threat by a check that has no rule "
                "entry of its own yet. The alert is real, its description is "
                "missing.",

    # Windows rules no longer used on Linux
    "EVT-1001": "Retired. Many failed Windows logins from one place.",
    "PRC-1002": "Retired. Microsoft Defender reported something.",

    # Processes
    "PRC-1001": "A running program has a name that appears on the suspicious "
                "names list. Weak on its own, since names are easy to fake.",

    # A remote Linux host watched over SSH
    "LNX-1001": "fail2ban on the watched server blocked an address that kept "
                "failing to log in.",
    "LNX-1002": "Someone failed to log in over SSH many times in a short "
                "period, which looks like password guessing.",
    "LNX-1003": "A login succeeded right after many failures from the same "
                "place. Password guessing may have worked. Check this first.",
    "LNX-1004": "The app reached the server but could not read any login "
                "logs, so it cannot tell you about logins there.",
    "LNX-1005": "A program with a suspicious name is running on the watched "
                "server.",
    "LNX-1006": "Scheduled jobs on the watched server changed since they were "
                "last recorded.",
    "LNX-1007": "An important file on the watched server changed since it was "
                "last recorded.",
    "LNX-1008": "A new program that runs with administrator rights appeared "
                "on the watched server.",

    # Accounts and logins on this machine
    "LNX-1009": "A new user account was created on this machine. Fine if you "
                "made it, serious if you did not.",
    "LNX-1010": "A user account was deleted on this machine. Fine if you did "
                "it, worth checking if you did not.",
    "LNX-1011": "A new SSH key was added, which lets someone log in without a "
                "password. Make sure you added it.",
    "LNX-1012": "Many failed login attempts on this machine in a short period, "
                "which looks like someone guessing a password.",
    "LNX-1013": "A background service keeps crashing and restarting. Usually "
                "a broken service rather than an attack.",
    "LNX-1014": "A background service was started many times in a short "
                "period. Either it is crashing or something keeps restarting "
                "it.",
    "LNX-1015": "One address kept trying to reach this machine and the "
                "firewall kept blocking it. Looks like someone probing for a "
                "way in.",
    "LNX-1016": "Many successful logins from one address in a short period. "
                "Could be a script, a misconfigured app or a stolen key.",
    "LNX-1017": "An account was given administrator power (added to sudo or a "
                "similar group). Make sure that was you.",
    "LNX-1018": "A driver that did not come from the official kernel was "
                "loaded. Normal for graphics or VirtualBox drivers, also how "
                "rootkits load.",
    "LNX-1101": "A program is running from a temporary folder. Installers do "
                "this, and so does dropped malware.",
    "LNX-1102": "A program uses the name of a system tool but is not the real "
                "one. Something may be disguising itself.",
    "LNX-1103": "A normal system tool is being used in a way attackers use, "
                "such as opening a remote shell or downloading and running a "
                "script.",

    # File and permission checks on this machine
    "LNX-2001": "An important system file changed, or a file was added or "
                "removed in a sensitive folder. Updates do this too.",
    "LNX-2002": "An SSH login key was added or removed for an account on this "
                "machine. Make sure you did it.",
    "LNX-2003": "The permissions on a login or key file changed. If it became "
                "writable by everyone, anyone could add themselves a key.",
    "LNX-2004": "A file that forces extra code into every program appeared or "
                "changed. It should not exist. Treat as serious.",
    "LNX-2005": "Some installed files could not be checked against what the "
                "package shipped. Unchecked, not necessarily bad.",
    "LNX-2006": "An installed program or library differs from what the "
                "package shipped. High for programs, medium for settings "
                "files you may have edited.",
    "LNX-2007": "A program that runs with administrator rights was added, "
                "changed, or lost that right.",
    "LNX-2008": "A program that runs with a group's rights was added, "
                "changed, or lost that right.",
    "LNX-2009": "A program's special privileges (Linux capabilities) were "
                "added, changed or removed.",
    "LNX-2010": "The permission check could not read part of the disk, so "
                "that part was not checked.",
    "LNX-2011": "A security system (AppArmor or SELinux) stopped enforcing "
                "its rules.",
    "LNX-2012": "A file was changed and its date was set back to hide the "
                "change. A deliberate cover-up pattern.",

    # Network and devices
    "NET-1001": "A device the app has not seen before answered on your "
                "network.",
    "NET-1002": "A device you said should always be online has stopped "
                "answering.",
    "RTR-1001": "The router reports a device the app had not seen yet.",
    "RTR-1002": "A router setting the app recorded has changed.",
    "PRB-1001": "A device you approved now looks different, as if it was "
                "replaced or is being impersonated.",
    "PRB-1002": "A device marked as always present was missing so long that "
                "it was removed from the device list.",

    # Things this app did, not things it saw
    "REM-1001": "Record: the app stopped a program because you told it to.",
    "REM-1002": "Record: the app blocked a port in the firewall.",
    "REM-1003": "Record: the app removed a port block it had added.",
    "REM-1004": "Record: the app blocked an address on this machine only.",
    "REM-1005": "Record: the app removed an address block on this machine.",
    "REM-1006": "Record: the app moved a file into quarantine.",
    "REM-1007": "Record: the app restored a file from quarantine.",
    "REM-1008": "Record: the app stopped a background service.",
    "REM-1009": "Record: the app blocked an address at the router, cutting it "
                "off from the internet.",
    "REM-1010": "Record: the app removed an address block at the router.",
    "REM-1011": "Record: the app made the router refuse to look up a domain, "
                "for every device using it.",
    "REM-1012": "Record: the app removed a domain block at the router.",
    "REM-1013": "Record: the app blocked a device at the router by its "
                "hardware address, whatever IP it uses.",
    "REM-1014": "Record: the app removed a device block at the router.",
    "REM-1015": "Record: the app blocked one app on one device at the router.",
    "REM-1016": "Record: the app removed an app block at the router.",
    "REM-1017": "Record: the app removed an SSH login key from an account.",
    "REM-1018": "Record: the app put back an SSH key it had removed.",
    "REM-1019": "Record: the app locked an account so nobody can log in to "
                "it.",
    "REM-1020": "Record: the app unlocked an account it had locked.",
    "REM-1021": "Record: the app took administrator power away from an "
                "account.",
    "REM-1022": "Record: the app gave back administrator power it had "
                "removed.",
    "REM-1023": "Record: the app switched off a scheduled job.",
    "REM-1024": "Record: the app switched a scheduled job back on.",
    "REM-1025": "Record: the app disabled a background service so it cannot "
                "start again.",
    "REM-1026": "Record: the app re-enabled a background service it had "
                "disabled.",

    # DNS lookups
    "DNS-1001": "A device looked up random-looking domain names. Malware "
                "does this to find its controller, though some websites use "
                "odd names too.",
    "DNS-1002": "A device looks up the same domain on a regular timer. "
                "Updaters do this, and so does malware checking in.",
    "DNS-1003": "A device sent lookups with encoded-looking data in the "
                "names. This can be a way of sneaking data out through DNS.",
    "DNS-1004": "A device made an unusually large number of DNS lookups. "
                "Often harmless, worth a look if it keeps happening.",
    "DNS-1005": "A device mostly looked up domains that do not exist. Either "
                "a misconfigured device or malware hunting for its "
                "controller.",
    "DNS-1006": "A device asked for an unusual number of text records (TXT). "
                "Some software does this, and it can also carry hidden data.",

    # Linux audit system
    "AUD-1001": "The rules deciding what the audit system records were "
                "changed. Someone may be turning off monitoring.",
    "AUD-1002": "A file or folder you asked the audit system to watch was "
                "touched. Usually expected.",
    "AUD-1003": "The audit system is switched off or losing records, so "
                "activity is not being logged. Turn it back on.",
    "AUD-1004": "The audit logging service stopped. Nothing is written to the "
                "audit log until it starts again.",

    # Antivirus
    "AV-1001": "ClamAV found known malware in a file.",

    # Your local network
    "LAN-1001": "Two devices are claiming the same network address. Can be a "
                "setup mistake or someone intercepting traffic (ARP "
                "spoofing).",
    "LAN-1002": "Your router suddenly looks like a different device. "
                "Expected if you replaced it, otherwise someone may be "
                "intercepting traffic.",
    "LAN-1003": "A second device is handing out network addresses (DHCP). "
                "Usually a second router, but it can redirect traffic.",
    "LAN-1004": "One device is answering name lookups meant for other "
                "devices. A known trick for stealing Windows passwords.",
    "LAN-1005": "Two devices are claiming the same IPv6 address. Can be a "
                "mistake or someone intercepting traffic.",
    "LAN-1006": "A new device is announcing itself as an IPv6 router. Often "
                "a phone hotspot, but it can redirect traffic.",
    "LAN-1007": "A new device is handing out IPv6 settings. Attack tools use "
                "this to take over name lookups.",
    "LAN-1008": "A device with a hardware address the app has never seen "
                "joined your network.",
    "LAN-1009": "A device uploaded far more than it normally does. Could be a "
                "backup, could be data leaving.",
    "LAN-1010": "A device connected to, or looked up, an address on a threat "
                "list.",
    "LAN-1011": "A device you blocked came back online with a new address.",

    # Threat feeds
    "FED-1001": "A device connected to an address that a public threat list "
                "names as a botnet controller.",
    "FED-1002": "A device looked up a domain that a public threat list names "
                "as serving malware.",
    "FED-1003": "A device started a secure connection to a site that a "
                "public threat list names as malicious.",

    # Kernel level process watching
    "LNX-3001": "A program started from a temporary or Downloads folder. "
                "Installers do this all the time, which is why it is low.",
    "LNX-3002": "A shell ran a script from a temporary folder. Check what "
                "the script did.",
    "LNX-3003": "A program connected to a port that hacking tools commonly "
                "use. The alert names the program.",
    "LNX-5001": "A program from a temporary folder, or one whose file was "
                "deleted, is listening to raw network traffic. A hidden "
                "backdoor pattern.",

    # Things set to start on their own
    "LNX-4001": "A background service is set up to run a suspicious command, "
                "such as downloading and running something.",
    "LNX-4002": "A scheduled job runs a suspicious command, such as "
                "downloading and running something.",
    "LNX-4003": "A shell startup file (like .bashrc) contains a suspicious "
                "command that runs every time you open a terminal.",
    "LNX-4004": "Something new was set to start automatically (a service, "
                "scheduled job or startup file).",
    "LNX-4005": "Something set to start automatically now does something "
                "different. Updates cause this too.",
    "LNX-4006": "Something set to start automatically was removed. Usually "
                "an uninstall.",

    # Place learning
    "GEO-1001": "A program or device reached a country it does not normally "
                "talk to. Medium when nothing in your home has talked to that "
                "country before.",
    "GEO-1002": "A program or device reached a network company it does not "
                "normally talk to.",

    "PRT-1001": "Retired. A scan found an open port.",
}
