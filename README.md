# Awesome-CobaltStrike-Defence
<h1>Defences against Cobalt Strike</h1>

<strong>Cobalt Strike is a commercial, full-featured, penetration testing tool which bills itself as "adversary simulation software designed to execute targeted attacks and emulate the post-exploitation actions of advanced threat actors". Cobalt Strike’s interactive post-exploit capabilities cover the full range of ATT&CK tactics, all executed within a single, integrated system.
In addition to its own capabilities, Cobalt Strike leverages the capabilities of other well-known tools such as Metasploit and Mimikatz. <strong>


Cobalt Strike MITRE TTPs </br>
https://attack.mitre.org/software/S0154/

Cobalt Strike MITRE ATT&CK Navigator </br>
https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS0154%2FS0154-enterprise-layer.json

<h2>Hunting & Detection Tools</br></h2>

Cobalt Strike Team Server Password Brute Forcer </br>
https://github.com/isafe/cobaltstrike_brute

CobaltStrikeScan Scan files or process memory for Cobalt Strike beacons and parse their configuration </br>
https://github.com/Apr4h/CobaltStrikeScan

Cobalt Strike beacon scan </br>
https://github.com/whickey-r7/grab_beacon_config

Cobalt Strike decrypt</br>
https://github.com/WBGlIl/CS_Decrypt

Detecting CobaltStrike for Volatility<br>
https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py

JARM fingerprints scanner </br>
https://github.com/salesforce/jarm

Cobalt Strike Forensic</br>
https://github.com/RomanEmelyanov/CobaltStrikeForensic

Cobalt Strike resources</br>
https://github.com/Te-k/cobaltstrike

List of C2 JARM including Cobalt Strike</br>
https://github.com/cedowens/C2-JARM

SilasCutler_JARM_Scan_CobaltStrike_Beacon_Config.json </br>
https://pastebin.com/DzsPgH9w


Detection Cobalt Strike stomp</br>
https://github.com/slaeryan/DetectCobaltStomp


ThreatHunting Jupyter Notebooks - Notes on Detecting Cobalt Strike Activity</br>
https://github.com/BinaryDefense/ThreatHuntingJupyterNotebooks/blob/main/Cobalt-Strike-detection-notes.md

Random C2 Profile Generator</br>
https://github.com/threatexpress/random_c2_profile

<h2>Yara rules</br></h2>
Cobalt Strike Yara</br>
https://github.com/Neo23x0/signature-base/blob/master/yara/apt_cobaltstrike.yar</br>
https://github.com/Neo23x0/signature-base/blob/master/yara/apt_cobaltstrike_evasive.yar</br>
https://github.com/Te-k/cobaltstrike/blob/master/rules.yar

<h2>Sigma rules</br></h2>
Cobalt Strike sigma rules</br>
Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner.</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml</br>
https://github.com/SigmaHQ/sigma/blob/master/rules/windows/sysmon/sysmon_cobaltstrike_process_injection.yml</br>
(check in the future for updates or new rules)

<h2>Indicators of compromise</br></h2>

Cobalt Strike hashes</br>
https://bazaar.abuse.ch/browse/yara/CobaltStrike/

https://bazaar.abuse.ch/browse/tag/CobaltStrike/

https://bazaar.abuse.ch/browse/tag/CobaltStrike%20beacon%20implant%20Zoom%20Meetings/

https://tria.ge/s?q=family%3Acobaltstrike

Possible Cobalt Strike Stager IOCs</br>
https://pastebin.com/54zE6cSj


List of Cobalt Strike servers
https://docs.google.com/spreadsheets/d/1bYvBh6NkNYGstfQWnT5n7cSxdhjSn1mduX8cziWSGrw/edit#gid=766378683

Possible Cobalt Strike ioc's</br>
https://pastebin.com/u/cobaltstrikemonitor

Cobalt Strike Trevor Profiles</br>
https://pastebin.com/yB6RJ63F

https://pastebin.com/7QnLN5u0

Cobalt Strike & Metasploit servers</br>
https://gist.github.com/MichaelKoczwara</br>

ThreatFox Database(Cobalt Strike)by abuse.ch</br>
https://threatfox.abuse.ch/browse/malware/win.cobalt_strike/

<h2>Hunting & Detection Research Articles</br></h2>

Analysing Cobalt Strike for fun and profit</br>
https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/

Cobalt Strike Remote Threads detection</br>
https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f
https://github.com/Neo23x0/sigma/blob/master/rules/windows/sysmon/sysmon_cobaltstrike_process_injection.yml

The art and science of detecting Cobalt Strike</br>
https://talos-intelligence-site.s3.amazonaws.com/production/document_files/files/000/095/031/original/Talos_Cobalt_Strike.pdf

Detecting Cobalt Strike Default Modules via Named Pipe Analysis</br>
https://labs.f-secure.com/blog/detecting-cobalt-strike-default-modules-via-named-pipe-analysis/

A Multi-Method Approach to Identifying Rogue Cobalt Strike Servers</b2>
https://go.recordedfuture.com/hubfs/reports/cta-2019-0618.pdf

How to detect Cobalt Strike activities in memory forensics</br>
https://www.andreafortuna.org/2020/11/22/how-to-detect-cobalt-strike-activity-in-memory-forensics/

Detecting Cobalt Strike by Fingerprinting Imageload Events</br>
https://redhead0ntherun.medium.com/detecting-cobalt-strike-by-fingerprinting-imageload-events-6c932185d67c

The Anatomy of an APT Attack and CobaltStrike Beacon’s Encoded Configuration </br>
https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/

CobaltStrike - beacon.dll : Your No Ordinary MZ Header</br>
https://tccontre.blogspot.com/2019/11/cobaltstrike-beacondll-your-not.html

GitHub-hosted malware calculates Cobalt Strike payload from Imgur pic</br>
https://www.bleepingcomputer.com/news/security/github-hosted-malware-calculates-cobalt-strike-payload-from-imgur-pic/

Detecting Cobalt Strike beacons in NetFlow data</br>
https://delaat.net/rp/2019-2020/p29/report.pdf

Volatility Plugin for Detecting Cobalt Strike Beacon</br>
https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html

Easily Identify Malicious Servers on the Internet with JARM</br>
https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a

Cobalt Strike Beacon Analysis</br>
https://isc.sans.edu/forums/diary/Quick+Tip+Cobalt+Strike+Beacon+Analysis/26818/

Hancitor infection with Pony, Evil Pony, Ursnif, and Cobalt Strike</br>
https://isc.sans.edu/forums/diary/Hancitor+infection+with+Pony+Evil+Pony+Ursnif+and+Cobalt+Strike/25532/

Attackers Exploiting WebLogic Servers via CVE-2020-14882 to install Cobalt Strike</br>
https://isc.sans.edu/forums/diary/Attackers+Exploiting+WebLogic+Servers+via+CVE202014882+to+install+Cobalt+Strike/26752/

Hiding in the Cloud: Cobalt Strike Beacon C2 using Amazon APIs</br>
https://rhinosecuritylabs.com/aws/hiding-cloudcobalt-strike-beacon-c2-using-amazon-apis/

Identifying Cobalt Strike team servers in the wild</br>
https://blog.fox-it.com/2019/02/26/identifying-cobalt-strike-team-servers-in-the-wild/

Multi-stage APT attack drops Cobalt Strike using Malleable C2 feature</br>
https://blog.malwarebytes.com/threat-analysis/2020/06/multi-stage-apt-attack-drops-cobalt-strike-using-malleable-c2-feature/

Operation Cobalt Kitty</br>
http://cdn2.hubspot.net/hubfs/3354902/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty.pdf

Detecting and Advancing In-Memory .NET Tradecraft</br>
https://www.mdsec.co.uk/2020/06/detecting-and-advancing-in-memory-net-tradecraft/

Analysing Fileless Malware: Cobalt Strike Beacon</br>
https://newtonpaul.com/analysing-fileless-malware-cobalt-strike-beacon/ </br>
CobaltStrike samples pass=infected</br>
https://www.dropbox.com/s/o5493msqarg3iyu/Cobalt%20Strike.7z?dl=0 

IndigoDrop spreads via military-themed lures to deliver Cobalt Strike</br>
https://blog.talosintelligence.com/2020/06/indigodrop-maldocs-cobalt-strike.html

Cobalt Group Returns To Kazakhstan</br>
https://research.checkpoint.com/2019/cobalt-group-returns-to-kazakhstan/

Striking Back at Retired Cobalt Strike: A look at a legacy vulnerability</br>
https://research.nccgroup.com/2020/06/15/striking-back-at-retired-cobalt-strike-a-look-at-a-legacy-vulnerability/

Azure Sentinel Quick-Deploy with Cyb3rWard0g’s Sentinel To-Go – Let’s Catch Cobalt Strike! </br>
https://www.blackhillsinfosec.com/azure-sentinel-quick-deploy-with-cyb3rward0gs-sentinel-to-go-lets-catch-cobalt-strike/

Cobalt Strike stagers used by FIN6</br>
https://malwarelab.eu/posts/fin6-cobalt-strike/

Malleable C2 Profiles and You</br>
https://haggis-m.medium.com/malleable-c2-profiles-and-you-7c7ab43e7929</br>
List of spawns from exposed Cobalt Strike C2</br>
https://gist.github.com/MHaggis/bdcd0e6d5c727e5b297a3e69e6c52286

C2 Traffic patterns including Cobalt Strike</br>
https://marcoramilli.com/2021/01/09/c2-traffic-patterns-personal-notes/

CobaltStrike Threat Hunting via named Pipes</br>
https://www.linkedin.com/feed/update/urn:li:activity:6763777992985518081/

Hunting for GetSystem in offensive security tools</br>
https://redcanary.com/blog/getsystem-offsec/

Hunting and Detecting Cobalt Strike</br>
https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/

Detecting Cobalt Strike with memory signatures</br>
https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures

How to detect CobaltStrike Command & Control communication</br>
https://underdefense.com/how-to-detect-cobaltstrike-command-control-communication/

Red Canary Threat Detection Report 2021 - Cobalt Strike</br>
https://redcanary.com/threat-detection-report/threats/cobalt-strike/


Detecting Exposed Cobalt Strike DNS Redirectors</br>
https://labs.f-secure.com/blog/detecting-exposed-cobalt-strike-dns-redirectors/

Decoding Cobalt Strike Traffic</br>
https://isc.sans.edu/diary/27322

Anatomy of Cobalt Strike’s DLL Stager</br>
https://blog.nviso.eu/2021/04/26/anatomy-of-cobalt-strike-dll-stagers/

malleable_c2_profiles</br>
https://gist.github.com/MHaggis/6c600e524045a6d49c35291a21e10752

pipes</br>
https://gist.github.com/MHaggis/6c600e524045a6d49c35291a21e10752#gistcomment-3624664

spawnto</br>
https://gist.github.com/MHaggis/6c600e524045a6d49c35291a21e10752#gistcomment-3624663

<h2>Trainings </br></h2>
Attack detection fundamentals including also Cobalt Strike detection</br>
https://labs.f-secure.com/blog/attack-detection-fundamentals-initial-access-lab-1</br>
https://labs.f-secure.com/blog/attack-detection-fundamentals-initial-access-lab-2</br>
https://labs.f-secure.com/blog/attack-detection-fundamentals-initial-access-lab-3</br>
https://labs.f-secure.com/blog/attack-detection-fundamentals-initial-access-lab-4</br>
https://www.youtube.com/watch?v=DDK_hC90kR8&feature=youtu.beh</br>


<h2>Videos</br></h2>

Malleable Memory Indicators with Cobalt Strike's Beacon Payload</br>
https://www.youtube.com/watch?v=93GyP-mEUAw&feature=emb_title


STAR Webcast: Spooky RYUKy: The Return of UNC1878</br>
https://www.youtube.com/watch?v=BhjQ6zsCVSc

Excel 4.0 Macros Analysis - Cobalt Strike Shellcode Injection</br>
https://www.youtube.com/watch?v=XnN_UWfHlNM

Profiling And Detecting All Things SSL With JA3<br>
https://www.youtube.com/watch?v=oprPu7UIEuk

Hunting beacons by Bartosz Jerzman (x33fcon conf)<br>
https://www.youtube.com/watch?v=QrSTnVlOIIA

Striking Back: Hunting Cobalt Strike Using Sysmon And Sentinel by Randy Pargman<br>
https://vimeo.com/517161342















