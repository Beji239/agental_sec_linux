# core/detection_why.py
# Why each rule exists and what to do when it fires, for the Detections page.
# Two short sentences or so each, in the same voice as detection_plain.

WHY = {
    # Packet capture
    "PKT-1001": ("Anything stealing your files has to send them out, and that "
                 "shows up as one device moving a lot of traffic. It is a "
                 "measure, so backups and updates set it off too.",
                 "Check which device it is and whether a backup, sync or big "
                 "download was running then. If you cannot name a reason, "
                 "look at where the traffic went."),
    "PKT-1002": ("A device taken over by malware checks in with its "
                 "controller on a timer. This catches that rhythm even when "
                 "the destination is on no threat list.",
                 "Look at where it calls. A known company such as Apple, "
                 "Google or your antivirus is an updater, say False alarm. An "
                 "unknown name or a bare address is worth digging into."),
    "PKT-1003": ("So a quiet stretch is never taken for a safe one when the "
                 "app simply could not keep up with the traffic.",
                 "Nothing to fix on the network. If it fires often, this "
                 "machine is short of power to capture at that rate."),
    "PKT-1010": ("Metasploit is a common toolkit for breaking into machines, "
                 "and its payloads have known byte patterns. Seeing one at "
                 "home is rare and rarely innocent.",
                 "Find the two devices in the alert. Unless you were running "
                 "a security test yourself, block the device and check it."),
    "PKT-1011": ("SQL injection is how attackers pull data out of a service "
                 "that keeps a database. This catches someone trying it "
                 "against a service in your home.",
                 "Find which service was targeted and from where. If it came "
                 "from inside, check that device. Keep the service up to "
                 "date."),
    "PKT-1012": ("Cross-site scripting plants code in a web page so it runs "
                 "in the next visitor's browser. This catches someone trying "
                 "it against a service in your home.",
                 "Find which service was targeted and from where. If it came "
                 "from inside, check that device. Keep the service up to "
                 "date."),
    "PKT-1013": ("Ports such as file sharing and remote desktop are the doors "
                 "attackers try first. It tells you someone outside is "
                 "knocking.",
                 "The internet is scanned all the time, so this is low. Make "
                 "sure the port is closed on the router. If nothing answered, "
                 "there is nothing to do."),
    "PKT-1014": ("An infected machine reaches out to its controller, because "
                 "outgoing traffic gets past most firewalls. This catches a "
                 "connection out to a port such tools favour.",
                 "Find which program made it, LNX-3003 names it when it fires "
                 "too. If you cannot account for it, block the address and "
                 "check the machine."),
    "PKT-1015": ("Most normal traffic leaves on a handful of well-known "
                 "ports. An odd one is where unknown programs and tunnels "
                 "tend to show up.",
                 "Find the program. Games, VPNs and chat apps use odd ports. "
                 "If it is one of yours, say False alarm."),
    "PKT-1016": ("A redirect message can quietly send your traffic through "
                 "another machine. From outside your network it has no honest "
                 "reason to exist.",
                 "Make sure this machine ignores redirects "
                 "(net.ipv4.conf.all.accept_redirects set to 0). Nothing else "
                 "to do unless they keep coming."),
    "PKT-1017": ("It sits next to PKT-1016 so a buggy device is not taken "
                 "for a hijack.",
                 "Usually nothing. Do not chase where the address seems to "
                 "be, it is garbled. If it fires a lot, find the device on "
                 "your network sending these, often old router firmware."),
    "PKT-1099": ("So a threat the traffic check found is never dropped just "
                 "because nobody wrote its rule entry yet.",
                 "Read the alert itself, it names what was found, and treat "
                 "it as seriously as its severity says."),

    # Processes
    "PRC-1001": ("Some hacking and mining tools keep their usual names, and "
                 "catching those is easy. A renamed copy slips past, which "
                 "is why it counts as weak.",
                 "Check where the program runs from and who started it. A "
                 "tool you installed yourself is fine, say False alarm or "
                 "mute it for that name."),

    # A remote Linux host watched over SSH
    "LNX-1001": ("fail2ban already did the blocking. This tells you the "
                 "watched server is under attack and that its defence "
                 "worked.",
                 "Usually nothing, bans from all over the internet are "
                 "normal. A ban of an address inside your home means a "
                 "device here is guessing passwords."),
    "LNX-1002": ("Password guessing over SSH is the commonest attack on any "
                 "server that faces the internet.",
                 "Make sure SSH accepts keys only, not passwords, and that "
                 "fail2ban or similar is running. If the address is inside "
                 "your home, check that device."),
    "LNX-1003": ("The one thing worse than password guessing is password "
                 "guessing that worked.",
                 "Check it now. If it was not you mistyping, change that "
                 "account's password, check its SSH keys and look at what "
                 "the session did."),
    "LNX-1004": ("A server with no logins in its log looks safe. This makes "
                 "sure you know the app could not see, rather than nothing "
                 "happened.",
                 "Check the account the app uses can read the login log, it "
                 "often needs the adm group, and that the server still writes "
                 "one."),
    "LNX-1005": ("Some hacking and mining tools keep their usual names, and "
                 "catching those on the server is easy.",
                 "Check where the program runs from and who started it. A "
                 "tool you installed is fine, say False alarm."),
    "LNX-1006": ("Scheduled jobs are a favourite way to come back after a "
                 "reboot. Every change to them should be one you know about.",
                 "Read the change in the alert. If you or an update made it, "
                 "say False alarm. If not, remove the job and find how it got "
                 "there."),
    "LNX-1007": ("Files such as passwd, shadow and sudoers decide who gets in "
                 "and who is root. A change nobody made is a takeover.",
                 "Find what changed and when. Updates touch some of these, "
                 "anything else you did not do needs checking right away."),
    "LNX-1008": ("A setuid program runs as root whoever starts it, so "
                 "planting one is a classic way to keep root.",
                 "Check which package owns it (dpkg -S and the path). No "
                 "package and you did not put it there: remove the bit and "
                 "investigate."),

    # This machine, from its logs
    "LNX-1009": ("A new account is a new way in, and an intruder often makes "
                 "one to keep access.",
                 "If you or an install made it, say False alarm. If not, lock "
                 "the account and check what it did."),
    "LNX-1010": ("Deleting an account can be cleaning up, or covering "
                 "tracks.",
                 "If you removed it, nothing to do. If not, find who did from "
                 "the time in the alert."),
    "LNX-1011": ("A key lets someone in without a password, and it keeps "
                 "working after the password changes.",
                 "Check the key is yours. If not, remove it, the app can do "
                 "this, and find how it was added."),
    "LNX-1012": ("Catches someone guessing passwords at the login screen, "
                 "sudo or SSH on this machine.",
                 "If it was you mistyping, say False alarm. If not, check "
                 "where the attempts came from and that the account has a "
                 "strong password."),
    "LNX-1013": ("A service that keeps crashing is down, and now and then "
                 "something tampered with it.",
                 "Run systemctl status on the unit in the alert and read its "
                 "log. This is rarely an attack."),
    "LNX-1014": ("A service started over and over is either crashing or "
                 "being cycled, sometimes to load changed code.",
                 "Run systemctl status on the unit in the alert and read its "
                 "log. Mute it for that unit if it is harmless."),
    "LNX-1015": ("Probing for open doors usually comes before an attack. The "
                 "firewall stopped it, this tells you who is trying.",
                 "Check the address. A device in your home doing this may be "
                 "infected, or it is a scanner you run. Mute it for that "
                 "address if it is yours."),
    "LNX-1016": ("Many logins in a short time can be a script, a broken "
                 "client, or someone using a stolen key.",
                 "Find the account and the address. If it is your own "
                 "automation, mute it for that address."),
    "LNX-1017": ("Being in sudo, docker or a similar group is as good as "
                 "being root. Adding an account there is how an intruder "
                 "keeps power.",
                 "If you did it, say False alarm. If not, take the account "
                 "out of the group, the app can do this, and check who "
                 "added it."),
    "LNX-1018": ("Kernel modules have full power over the machine, and "
                 "rootkits load this way.",
                 "Check the module name. NVIDIA, VirtualBox and other drivers "
                 "you installed are normal, mute it for that name. An unknown "
                 "name needs a look."),

    # This machine, running programs
    "LNX-1101": ("Malware often runs from /tmp or /dev/shm, because any "
                 "account can write there.",
                 "Check what the program is and what started it. Installers "
                 "and updaters do this, say False alarm for ones you know."),
    "LNX-1102": ("A fake sshd or systemd hides in the process list by "
                 "borrowing a trusted name.",
                 "Check the real path of the program (ls -l /proc/PID/exe). "
                 "If it is not the system copy, stop it and investigate."),
    "LNX-1103": ("Attackers prefer tools already on the machine, such as "
                 "bash, curl and python, so nothing new has to be installed.",
                 "Read the command line in the alert. Your own scripts are "
                 "fine. A shell connected to a remote address is serious."),

    # This machine, file checks
    "LNX-2001": ("Files in /etc and folders such as sudoers.d and pam.d "
                 "decide who gets in and what runs at boot.",
                 "Compare with recent updates or your own edits. If neither "
                 "explains it, look at the change before anything else."),
    "LNX-2002": ("A key lets someone in without a password, from anywhere, "
                 "and survives a password change.",
                 "Check it was you. A key you did not add: remove it and find "
                 "how it got there."),
    "LNX-2003": ("If a login file becomes writable by others, any account on "
                 "the machine can give itself a key.",
                 "Put the permissions back (600 for authorized_keys, 700 for "
                 ".ssh) and check no key was added."),
    "LNX-2004": ("/etc/ld.so.preload makes every program load extra code "
                 "first. Many Linux rootkits hide this way, and a normal "
                 "system has no such file.",
                 "Treat it as serious. Read the file and the library it "
                 "names. If you did not set it up, take the machine off the "
                 "network and investigate."),
    "LNX-2005": ("So a file that could not be checked is never reported as "
                 "fine.",
                 "Usually a half-finished update or a removed package. Run "
                 "sudo dpkg --verify, and reinstall the package named if "
                 "files are missing."),
    "LNX-2006": ("Swapping a system program or library in place is how a "
                 "backdoor hides under a trusted name.",
                 "Reinstall the package named in the alert (sudo apt install "
                 "--reinstall and the name). For a settings file you edited, "
                 "say False alarm."),
    "LNX-2007": ("A setuid program runs as root whoever starts it, so a new "
                 "or changed one is a way to become root.",
                 "Check which package owns it (dpkg -S and the path). An "
                 "update explains most changes, a new file no package owns "
                 "does not."),
    "LNX-2008": ("A setgid program runs with a group's rights, a quieter "
                 "way to hand out power than setuid.",
                 "Check which package owns it (dpkg -S and the path). An "
                 "update explains most changes."),
    "LNX-2009": ("Capabilities hand out pieces of root power, such as raw "
                 "network access, more quietly than setuid.",
                 "Check the file and its package. Ping and a few network "
                 "tools carry these normally."),
    "LNX-2010": ("So a part of the disk the check could not read is never "
                 "reported as clean.",
                 "Usually a permission or a network drive. If it is a system "
                 "folder, find why it could not be read."),
    "LNX-2011": ("AppArmor or SELinux limit what a hacked program can do. "
                 "Switched off or to complain mode, they only watch.",
                 "If you did not change it, put it back to enforcing and find "
                 "what turned it off."),
    "LNX-2012": ("Putting a file's date back makes a change look old. Few "
                 "normal tools do that.",
                 "Treat it as serious. Compare the file with its package or "
                 "a backup."),

    # Devices on the network
    "NET-1001": ("Every device on your network can see and talk to the rest. "
                 "One you do not know is the first thing to check.",
                 "Find it on the Devices tab and name it if it is yours. If "
                 "you cannot place it, block it."),
    "NET-1002": ("A camera, storage box or alarm going silent can be a fault, "
                 "or someone switching it off.",
                 "Check the device has power and network. If you unplugged "
                 "it, there is nothing to do."),
    "RTR-1001": ("The router sees devices the app can miss, such as ones that "
                 "join and leave quickly.",
                 "Find it on the Devices tab and name it if it is yours. If "
                 "you cannot place it, block it."),
    "RTR-1002": ("Router settings such as DNS servers and port forwards decide "
                 "where all your traffic goes.",
                 "If you or a firmware update made the change, say False "
                 "alarm. If not, change it back and change the router "
                 "password."),
    "PRB-1001": ("A trusted device that now looks different may have been "
                 "swapped, or something is pretending to be it.",
                 "If you replaced or reset it, approve it again. If not, "
                 "check what is answering at that address."),
    "PRB-1002": ("So a device you said is always there does not vanish from "
                 "the list without a word.",
                 "If it is gone for good, nothing to do. If not, check it and "
                 "add it back."),

    # Name lookups
    "DNS-1001": ("Some malware makes up new random names every day to find "
                 "its controller, faster than block lists can follow.",
                 "Look at the names. Long hashes under a company you know are "
                 "content servers, say False alarm. Many random names from "
                 "one device are worth checking."),
    "DNS-1002": ("Malware checking in through DNS asks for the same name on "
                 "a timer.",
                 "Look at the name. A known service such as apple.com is an "
                 "app, say False alarm and the model learns it. An unknown "
                 "one needs a look."),
    "DNS-1007": ("One unknown server checking in with several of your "
                 "devices is the shape of one controller running them all.",
                 "Find the server and the devices. Treat it as serious until "
                 "you can name the app that does it."),
    "DNS-1008": ("So a quiet rule made for one device cannot hide the same "
                 "server spreading to others.",
                 "Check the new devices should talk to it. If not, undo the "
                 "quiet rule on the Expectations tab."),
    "DNS-1003": ("Data can be smuggled out inside name lookups, which get "
                 "past most firewalls.",
                 "Look at the names. Some analytics and security tools look "
                 "like this, an unknown domain from one device is worth "
                 "checking."),
    "DNS-1004": ("A sudden flood of lookups can be a broken app, or malware "
                 "searching for something.",
                 "Usually harmless. If it keeps happening on the same device, "
                 "find which app does it."),
    "DNS-1005": ("Malware trying made-up names to find its controller gets "
                 "mostly no such name back.",
                 "Check the names in the alert. A wrong search domain setting "
                 "is common, random names are not."),
    "DNS-1006": ("Text records can carry anything, so they are an easy "
                 "hidden way out.",
                 "Check the domain. Mail checks and some apps use them, many "
                 "from one device to an unknown domain need a look."),

    # Audit log
    "AUD-1001": ("Changing what the audit system records is how someone hides "
                 "what they do next. This rule watches the watching.",
                 "If you changed the audit rules, nothing to do. If not, find "
                 "who did and put them back."),
    "AUD-1002": ("Reports when a file or folder you chose to watch is "
                 "touched, and by whom.",
                 "Usually expected. If the account that touched it surprises "
                 "you, look closer."),
    "AUD-1003": ("With auditing off nothing is written down, and every quiet "
                 "answer after that is wrong.",
                 "Turn it back on with the command in the alert and find out "
                 "what turned it off."),
    "AUD-1004": ("While the audit service is stopped, nothing reaches the "
                 "audit log.",
                 "Updates restart it. If it does not come back by itself, run "
                 "sudo systemctl start auditd."),

    # Virus scanner
    "AV-1001": ("ClamAV knows a great many malware files by their "
                "fingerprint. A match is strong evidence.",
                "Quarantine the file, the app can do this, and find how it "
                "got there. A test file such as EICAR is harmless."),

    # Devices on your network, from the traffic
    "LAN-1001": ("Spoofing an address lets one device sit between others and "
                 "read their traffic.",
                 "Find the two hardware addresses in the alert. Two devices "
                 "set to the same fixed address is a mistake, otherwise check "
                 "the one you do not know."),
    "LAN-1002": ("Pretending to be your router is the easiest way to see all "
                 "your traffic.",
                 "If you replaced or reset the router, nothing to do. If not, "
                 "treat it as serious and find the new hardware address."),
    "LAN-1003": ("A fake address server can tell your devices to use it as "
                 "their router and DNS.",
                 "Find the device. A second router or mesh point not set to "
                 "access point mode is the usual cause, switch off its DHCP."),
    "LAN-1004": ("Tools such as Responder answer every name lookup to collect "
                 "Windows passwords.",
                 "Find the device answering. Unless you run such a tool, "
                 "check it. On Windows machines, turn off LLMNR and NetBIOS."),
    "LAN-1005": ("Spoofing an IPv6 address lets one device sit between others "
                 "and read their traffic.",
                 "Find the two hardware addresses in the alert and check the "
                 "one you do not know."),
    "LAN-1006": ("A fake IPv6 router can take over traffic even on a network "
                 "you think is IPv4 only.",
                 "Phone hotspots and second routers do this by accident. If "
                 "you cannot place the device, block it."),
    "LAN-1007": ("Attack tools such as mitm6 use this to become every "
                 "device's DNS server.",
                 "Find the device. If it is not a router you run, block it."),
    "LAN-1008": ("Catches a new device within a minute of joining, by its "
                 "hardware address.",
                 "Find it on the Devices tab and name it if it is yours. If "
                 "you cannot place it, block it."),
    "LAN-1009": ("Data leaving your home shows up as a device uploading far "
                 "more than usual.",
                 "Check whether a backup, cloud sync or video call explains "
                 "it. If not, look at where the device sent it."),
    "LAN-1010": ("Threat lists name places known for malware or botnet "
                 "control. Reaching one is rarely chance.",
                 "Check the device. Big shared hosts on a list cause false "
                 "alarms, say False alarm for those."),
    "LAN-1011": ("A blocked device that changes its address to get back "
                 "online is getting round the block.",
                 "Block it by hardware address at the router, so a new "
                 "address does not help it."),

    # Public threat lists
    "FED-1001": ("Botnet controllers are tracked on public lists. A device "
                 "talking to one is likely infected.",
                 "Block the device or the address, then check the device."),
    "FED-1002": ("Asking for a malware domain means something on the device "
                 "wanted to reach it.",
                 "Check the device and what it was doing. A big shared host "
                 "on the list can cause false alarms."),
    "FED-1003": ("Stronger than a lookup, because the connection was "
                 "actually tried, and it works even with encrypted DNS.",
                 "Check the device and what it was doing. A big shared host "
                 "on the list can cause false alarms."),

    # Kernel level process watching
    "LNX-3001": ("Malware often runs from temporary or download folders. The "
                 "kernel sees it start even if it exits within a second.",
                 "Check what it is. Installers and updaters do this every "
                 "day, say False alarm for ones you know."),
    "LNX-3002": ("A shell running a script from /tmp means something chose "
                 "to run that script.",
                 "Read the script if it is still there and check what it "
                 "started."),
    "LNX-3003": ("Names the program behind a connection to a hacking-tool "
                 "port, which the network capture cannot do.",
                 "Check the program. If you cannot account for it, stop it "
                 "and block the address."),
    "LNX-5001": ("Backdoors such as BPFDoor wait for a magic packet with no "
                 "open port, so no port scan can find them.",
                 "Treat it as serious. Check the program and where it came "
                 "from, a deleted file still running is a strong sign."),

    # Things set to start on their own
    "LNX-4001": ("Malware makes itself a service so it starts at every boot.",
                 "Read the quoted line. Some system services match by "
                 "accident, say False alarm for ones you know."),
    "LNX-4002": ("Malware adds a scheduled job so it comes back on its own.",
                 "Read the quoted command. Remove the job if you did not "
                 "put it there."),
    "LNX-4003": ("A line in .bashrc runs every time you open a terminal, "
                 "which makes it a quiet backdoor.",
                 "Read the line. Remove it if you did not put it there."),
    "LNX-4004": ("Anything that starts on its own survives a reboot. New "
                 "ones should be ones you installed.",
                 "If you just installed something, say False alarm. If not, "
                 "check what it runs."),
    "LNX-4005": ("Changing what an existing start item runs is quieter than "
                 "adding a new one.",
                 "The alert shows the old and the new. Updates do this, check "
                 "the new one makes sense."),
    "LNX-4006": ("Removing a start item can be an uninstall, or someone "
                 "cleaning up after themselves.",
                 "If you uninstalled something, nothing to do."),

    # Place learning
    "GEO-1001": ("A program or device suddenly talking to a new country can "
                 "be a new app, or data going somewhere it should not.",
                 "Check the program or device and where it went. A new app "
                 "explains most, say False alarm for those."),
    "GEO-1002": ("A program or device suddenly talking to a new network "
                 "company can be a new app, or something it should not do.",
                 "Check the program or device and where it went. A new app "
                 "explains most, say False alarm for those."),

    # The app's own sensors
    "SYS-1001": ("A sensor that stops makes its part of the app go quiet, "
                 "and quiet looks like safe. This tells you it is blind.",
                 "Check the app's log for why it stopped, and restart the app "
                 "if it does not come back by itself."),
    "SYS-1002": ("Closes the gap SYS-1001 opened, so you know when watching "
                 "started again.",
                 "Nothing to do. Anything during the gap was not recorded."),
}

# Records and retired rules share one answer each.
RECORD = ("Every change the app makes is written down, so you can check it "
          "was asked for and undo it.",
          "Nothing to do if you asked for it. If you do not remember asking, "
          "undo it and find what asked.")
RETIRED = ("Kept so old alerts still say where they came from. It no longer "
           "fires.",
           "Nothing to do.")


def why_for(did: str, kind: str, retired: bool) -> tuple[str, str]:
    if retired:
        return RETIRED
    if kind == "action_record":
        return RECORD
    return WHY.get(did, ("", ""))
