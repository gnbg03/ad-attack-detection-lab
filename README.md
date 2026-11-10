# Attack & Detection Lab: Wazuh SIEM on a Windows Active Directory Domain

A follow-on to my [Windows AD home lab](https://github.com/gnbg03/windows-ad-home-lab): a Wazuh SIEM was added to the same domain, Windows auditing was turned on, and the domain controller was attacked from a Kali Linux VM (reconnaissance and a Kerberos password spray) to see what a real SIEM does and does not catch out of the box, and to build a custom detection rule on top of it.

## Environment

| VM | Role | Network |
|---|---|---|
| DC01 | Windows Server 2025 domain controller (`lab.local`) | `192.168.50.10` |
| WIN11-01 | Domain-joined Windows 11 client | `192.168.50.100` |
| WAZUH01 | Ubuntu Server 24.04, Wazuh indexer + manager + dashboard (all-in-one) | `192.168.50.20` |
| Kali | Attacker VM (Nmap, Kerbrute) | `192.168.50.101` |

All four sit on an isolated VirtualBox Internal Network (`labnet`, `192.168.50.0/24`); only each VM's second NAT adapter reaches the internet, and that adapter was disconnected on Kali before any attack.

## What was built

1. **Wazuh server (WAZUH01).** Installed with the all-in-one assistant (indexer, manager, dashboard on one host). Hit two real install failures along the way (see Troubleshooting) before it came up clean.
2. **Wazuh agent on DC01**, deployed from the dashboard's guided installer, pointed at the manager's lab address.
3. **Windows audit policy**, pushed via a new Group Policy Object linked to the Domain Controllers OU: Logon, Account Lockout, User and Security Group Management, Credential Validation, and both Kerberos categories, all set to Success and Failure, with the subcategory-override setting enabled so the detailed policy actually takes effect.
4. **A Kali Linux attacker VM** on the same isolated network.
5. **A custom Wazuh correlation rule** that watches specifically for repeated Kerberos pre-authentication failures from one source.

## Attacks run and what they produced

### 1. Reconnaissance (Nmap)

```
nmap -sn 192.168.50.0/24
nmap -sV -sC 192.168.50.10
```

Fully fingerprinted DC01 as a domain controller: DNS, Kerberos, LDAP (domain `lab.local`), SMB (signing enabled and required), and the hostname. **Result in Wazuh: nothing attributable to the scan.** A network port scan doesn't touch the Windows Security event log, and the Wazuh Windows agent reads logs, not packets, so it's invisible to this setup. The alert volume on the dashboard during the scan window turned out to be unrelated background DC logon activity, not the scan itself. Detecting this would need a network-based tool (Suricata, Zeek) in addition to a host agent — a real limitation of this lab, not a configuration mistake.

### 2. Password spray (Kerbrute)

```
kerbrute passwordspray -d lab.local --dc 192.168.50.10 users.txt <password>
```

Run several times against a 6-account list with passwords none of the accounts use (0 successes each time, as expected — the goal was to generate detectable failure traffic, not to get in). Each failed attempt produces a Windows event **4771** (Kerberos pre-authentication failed) on the domain controller, which the agent ships to Wazuh.

## Detection results

| Layer | Rule | What it catches |
|---|---|---|
| Baseline | 60122 (built-in) | A single failed interactive logon (event 4625) |
| Baseline | 60104 (built-in) | A generic Windows audit failure (covers 4771, among others) |
| Correlation | **60205 (built-in)** | 8+ audit failures from the same source IP within 240 seconds — fired correctly on the spray, with no custom work |
| Custom, specific | **100099 (mine)** | Matches only event 4771 out of the broader 60104 group |
| Custom, correlated | **100100 (mine)** | 5+ matches of 100099 from the same source IP within 120 seconds, tagged with MITRE T1110.003 |

**What the custom rules add over the built-in ones:** 60205 will fire on any mix of repeated audit failures from one source, whatever the cause. Rule 100099 narrows that down to Kerberos pre-authentication failures specifically, and 100100 gives that narrower signal its own threshold, description, and MITRE mapping, rather than relying on the generic 60205 description to explain what happened.

**What I attempted and didn't ship:** I tried extending 100100 with a `different_field` check on the target username, so it would only fire when the failures hit several *different* accounts (a real spray) rather than one account retried several times (a brute force). It worked once in testing, then failed to reproduce across five further attempts with data that looked correct, including after ruling out stale search windows, unsaved file edits, and a missing base rule (I found and fixed that last one — see Troubleshooting). I could not pin down the cause in the time I had, so the shipped version of 100100 does not include the distinct-account check. It still reliably detects a burst of Kerberos failures from one source, which covers both a spray and a single-account brute force.

## MITRE ATT&CK mapping

| Technique | Name | How it showed up here |
|---|---|---|
| T1046 | Network Service Discovery | Nmap scan of DC01 — not visible in Wazuh (host-agent limitation) |
| T1110.003 | Brute Force: Password Spraying | Kerbrute spray — caught by built-in 60205 and custom rule 100100 |

## Troubleshooting log

**1. Wazuh install hung on the indexer with kernel `rcu_preempt` stall warnings.** The VM was running under Windows' Hyper-V platform (a green turtle icon in VirtualBox's status bar), which badly throttles CPU-heavy guests. Disabling the Hyper-V launch type on the host (`bcdedit /set hypervisorlaunchtype off`, plus turning off the related Windows features) fixed it outright — the indexer install time dropped from over 7 minutes (failing) to about 25 seconds.

**2. A later install attempt failed with `No space left on device` during the dashboard step**, despite plenty of free disk, free inodes, and free `/run` space at every check. The install's own cleanup removed the dashboard package but left the `wazuh-manager` package record in a broken half-removed state, which then blocked every subsequent install attempt with `wazuh-manager already installed` / later `wazuh-keystore: No such file or directory`. Fixed by moving the package's failing pre/post-removal scripts out of the way and force-purging the stale package record before reinstalling clean.

**3. Dashboard login failed with "Invalid username or password" even though the saved password was correct**, verified directly against the indexer with `curl -u admin:<password> https://localhost:9200`. Root cause unclear — most likely a misread lookalike character (the generated password mixes `I`/`l`/`O`/`0`) when typing it rather than pasting it. Resolved by connecting over SSH (added a port-forward) and pasting the password instead of typing it.

**4. Custom rule development took several rounds to get right**, each caught by the manager's own log rather than a validator (`wazuh-logtest -t` and `wazuh-analysisd -t` were not valid options in this version):
   - `frequency`/`timeframe` have to be attributes on the `<rule>` tag itself, not separate child elements.
   - A frequency-counting rule needs `if_matched_sid`, not `if_sid` — the latter doesn't track repeated matches over time.
   - A generic base rule (60104) let an unrelated event type into the frequency count; splitting out a 4771-specific rule (100099) and chaining the frequency rule off that fixed it.
   - A full-file edit once dropped rule 100099 from the file entirely while "simplifying" rule 100100 — `if_matched_sid` was then pointing at a rule that no longer existed, with no error from the manager, since nothing was syntactically wrong. Caught by re-reading the full file contents rather than assuming the edit matched what was intended.
   - The `different_field` (distinct-account) refinement fired once, then stopped reproducing across repeated clean tests with correct-looking data, and was dropped rather than shipped in an unverified state.

## Next steps

- Investigate why `different_field` didn't reproduce, with a longer gap between test runs and a single spray at a time
- Add a Kerberoasting attack (request and crack a service ticket) and its corresponding detection
- Forward DC01's logs to a second detection tool for comparison
- Add network-level monitoring to cover what the Nmap scan showed was invisible to a host agent alone

## Screenshots

**1. Wazuh dashboard home page after installation: no agents yet, alert severity summary**

![Wazuh dashboard home page after installation: no agents yet, alert severity summary](screenshots/01-wazuh-dashboard-overview.png)

**2. Deploy new agent wizard: Windows MSI package, server address 192.168.50.20, agent name DC01**

![Deploy new agent wizard: Windows MSI package, server address 192.168.50.20, agent name DC01](screenshots/02-deploy-agent-wizard-1.png)

**3. Deploy new agent wizard: generated install and start commands for the DC01 agent**

![Deploy new agent wizard: generated install and start commands for the DC01 agent](screenshots/03-deploy-agent-wizard-2.png)

**4. Wazuh agent install commands run in an elevated PowerShell on DC01; service started successfully**

![Wazuh agent install commands run in an elevated PowerShell on DC01; service started successfully](screenshots/04-agent-install-on-dc01.png)

**5. DC01 listed as an Active agent in the Wazuh dashboard, running Windows Server 2025, agent v4.14.10**

![DC01 listed as an Active agent in the Wazuh dashboard, running Windows Server 2025, agent v4.14.10](screenshots/05-agent-active-in-dashboard.png)

**6. Wazuh service running on DC01; Test-NetConnection confirms ports 1514 and 1515 reach the manager**

![Wazuh service running on DC01; Test-NetConnection confirms ports 1514 and 1515 reach the manager](screenshots/06-agent-service-and-ports.png)

**7. New-GPO and New-GPLink: DC Audit Policy created and linked to the Domain Controllers OU**

![New-GPO and New-GPLink: DC Audit Policy created and linked to the Domain Controllers OU](screenshots/07-audit-gpo-created.png)

**8. auditpol /get output: Logon, Account Lockout, User/Security Group Management, and Kerberos categories all set to Success and Failure**

![auditpol /get output: Logon, Account Lockout, User/Security Group Management, and Kerberos categories all set to Success and Failure](screenshots/08-auditpol-full-coverage.png)

**9. Baseline test: a bad-password console logon on DC01 appears as rule 60122 (event 4625, Logon Failure)**

![Baseline test: a bad-password console logon on DC01 appears as rule 60122 (event 4625, Logon Failure)](screenshots/09-baseline-4625-event.png)

**10. Kali VM network: eth0 on the isolated lab network (192.168.50.101 via DHCP), eth1 on NAT for updates**

![Kali VM network: eth0 on the isolated lab network (192.168.50.101 via DHCP), eth1 on NAT for updates](screenshots/10-kali-network-config.png)

**11. Kali can reach DC01 (192.168.50.10) and WAZUH01 (192.168.50.20) over the lab network**

![Kali can reach DC01 (192.168.50.10) and WAZUH01 (192.168.50.20) over the lab network](screenshots/11-kali-connectivity.png)

**12. Nmap service scan of DC01 from Kali: DNS, Kerberos, LDAP, SMB, and the domain lab.local fingerprinted**

![Nmap service scan of DC01 from Kali: DNS, Kerberos, LDAP, SMB, and the domain lab.local fingerprinted](screenshots/12-nmap-scan-of-dc01.png)

**13. Wazuh activity during the Nmap scan: only ordinary DC01 logon noise, no events tied to the scan itself**

![Wazuh activity during the Nmap scan: only ordinary DC01 logon noise, no events tied to the scan itself](screenshots/13-wazuh-during-nmap-scan.png)

**14. Kerbrute built from source on Kali and its command help**

![Kerbrute built from source on Kali and its command help](screenshots/14-kerbrute-built.png)

**15. First password spray: 6 accounts tested against one password, 0 successes, in 0.022 seconds**

![First password spray: 6 accounts tested against one password, 0 successes, in 0.022 seconds](screenshots/15-kerbrute-spray-run1.png)

**16. Wazuh's built-in rule 60205 (Multiple Windows audit failure events) firing on the spray traffic, level 10**

![Wazuh's built-in rule 60205 (Multiple Windows audit failure events) firing on the spray traffic, level 10](screenshots/16-wazuh-60205-correlation.png)

**17. Definition of the built-in rule 60205: triggers on repeated audit failures from the same source IP within 240 seconds**

![Definition of the built-in rule 60205: triggers on repeated audit failures from the same source IP within 240 seconds](screenshots/17-rule-60205-definition.png)

**18. First draft of the custom local rule (100100) in local_rules.xml**

![First draft of the custom local rule (100100) in local_rules.xml](screenshots/18-custom-rule-first-draft.png)

**19. Manager rejects the rule: frequency/timeframe must be attributes of <rule>, not separate child tags**

![Manager rejects the rule: frequency/timeframe must be attributes of <rule>, not separate child tags](screenshots/19-rule-syntax-error-frequency.png)

**20. A second XML error (unclosed attribute) caught from the manager's own log before the rule would load**

![A second XML error (unclosed attribute) caught from the manager's own log before the rule would load](screenshots/20-rule-syntax-error-xml.png)

**21. Rule split into a specific 4771-matching base rule (100099) and a frequency rule built on top of it (100100)**

![Rule split into a specific 4771-matching base rule (100099) and a frequency rule built on top of it (100100)](screenshots/21-rule-fixed-splitting-base-rule.png)

**22. Custom base rule 100099 reliably matching every Kerberos pre-authentication failure (event 4771)**

![Custom base rule 100099 reliably matching every Kerberos pre-authentication failure (event 4771)](screenshots/22-rule-100099-working.png)

**23. The frequency-based rule 100100 fired successfully in one test run, confirming the approach works**

![The frequency-based rule 100100 fired successfully in one test run, confirming the approach works](screenshots/23-rule-100100-fired-once.png)

**24. Final local_rules.xml: rule 100099 (4771 detector) plus rule 100100 (frequency correlation), confirmed loaded with no errors**

![Final local_rules.xml: rule 100099 (4771 detector) plus rule 100100 (frequency correlation), confirmed loaded with no errors](screenshots/24-local-rules-final-content.png)

**25. Final proof: rule 100099 matched 20 times across two sprays, in the Wazuh dashboard**

![Final proof: rule 100099 matched 20 times across two sprays, in the Wazuh dashboard](screenshots/25-rule-100099-final-proof.png)



## Evidence files

Full Wazuh alert documents (PDF), with complete event and rule detail: `evidence-4625-failed-logon.pdf`, `evidence-4771-tuser-attempt1.pdf`, `evidence-4771-tuser-attempt2.pdf`, `evidence-4771-administrator-console.pdf`.
