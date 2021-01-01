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

Cobalt Strike resources</br>
https://github.com/Te-k/cobaltstrike

List of C2 JARM including Cobalt Strike</br>
https://github.com/cedowens/C2-JARM

<h2>Yara rules</br></h2>
Cobalt Strike Yara</br>
https://github.com/Neo23x0/signature-base/blob/master/yara/apt_cobaltstrike.yar</br>
https://github.com/Neo23x0/signature-base/blob/master/yara/apt_cobaltstrike_evasive.yar</br>
https://github.com/Te-k/cobaltstrike/blob/master/rules.yar

<h2>Indicators of compromise</br></h2>

Cobalt Strike hashes</br>
https://bazaar.abuse.ch/browse/yara/CobaltStrike/

List of Cobalt Strike servers
https://docs.google.com/spreadsheets/d/1bYvBh6NkNYGstfQWnT5n7cSxdhjSn1mduX8cziWSGrw/edit#gid=766378683



<h2>Hunting & Detection Research</br></h2>
Detection Cobalt Strike stomp</br>
https://github.com/slaeryan/DetectCobaltStomp

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

The Anatomy of an APT Attack and CobaltStrike Beacon’s Encoded Configuration</b2>
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
https://newtonpaul.com/analysing-fileless-malware-cobalt-strike-beacon/
CobaltStrike samples pass=infected
https://www.dropbox.com/s/o5493msqarg3iyu/Cobalt%20Strike.7z?dl=0 

IndigoDrop spreads via military-themed lures to deliver Cobalt Strike</br>
https://blog.talosintelligence.com/2020/06/indigodrop-maldocs-cobalt-strike.html

Cobalt Group Returns To Kazakhstan</br>
https://research.checkpoint.com/2019/cobalt-group-returns-to-kazakhstan/

Striking Back at Retired Cobalt Strike: A look at a legacy vulnerability</br>
https://research.nccgroup.com/2020/06/15/striking-back-at-retired-cobalt-strike-a-look-at-a-legacy-vulnerability/


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

Profiling And Detecting All Things SSL With JA3
https://www.youtube.com/watch?v=oprPu7UIEuk















