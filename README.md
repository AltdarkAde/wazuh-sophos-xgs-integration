# Sophos XGS Firewall → Wazuh SIEM

Syslog integration with custom decoder and rules so every authentication failure, admin configuration change, VPN login, and brute-force attempt produces an alert with **username and source IP** visible.

📝 Original article: [Integrating Sophos XGS Firewall with Wazuh SIEM](https://medium.com/@aabiodunadeleke/integrating-sophos-xgs-firewall-with-wazuh-siem-a-complete-step-by-step-guide-bc09b50fa60b)

## Outcome

- Sophos XGS sends logs to Wazuh over syslog (UDP 5514)
- Custom decoder parses all XGS fields (the built-in Sophos decoder expects the older `device="SFW"` format; XGS starts with `device_name=`)
- Rules for auth failures, admin changes, VPN logins, brute force, and IPSec events
- Works with multiple branch firewalls (handles `device_name` being either `SFW` or a hostname)

## Architecture

```
Sophos XGS (branch 1..n) --syslog/UDP 5514--> wazuh-remoted --> decoder (sophos-xgs) --> rules 1101xx --> alerts / email (level 7+)
```

## Files

| File | Destination on Wazuh manager |
|---|---|
| [`decoders/sophos-xgs-decoders.xml`](decoders/sophos-xgs-decoders.xml) | `/var/ossec/etc/decoders/local_decoder.xml` |
| [`rules/sophos-xgs-rules.xml`](rules/sophos-xgs-rules.xml) | `/var/ossec/etc/rules/local_rules.xml` |
| [`samples/test-logs.txt`](samples/test-logs.txt) | Paste into `wazuh-logtest` |

## Prerequisites

- Wazuh Manager (tested on v4.14), root/sudo access
- Sophos XGS with admin access
- UDP 5514 reachable from the firewall to the Wazuh server

## Steps

### 1. Confirm Wazuh is listening for syslog

```bash
sudo grep -A6 "connection>syslog" /var/ossec/etc/ossec.conf
sudo ss -ulnp | grep 5514
```

If missing, add inside `<ossec_config>`:

```xml
<remote>
  <connection>syslog</connection>
  <port>5514</port>
  <protocol>udp</protocol>
  <allowed-ips>FIREWALL_IP/32</allowed-ips>
  <local_ip>0.0.0.0</local_ip>
</remote>
```

Expected: `wazuh-remoted` bound to `0.0.0.0:5514`.

### 2. Configure Sophos XGS

**System → Log Settings → Syslog → Add**

| Setting | Value |
|---|---|
| IP address | Wazuh server IP |
| Port | 5514 |
| Protocol | UDP |
| Log format | Device Standard Format |
| Facility | LOCAL0 |

Enable at least **Event**, **Firewall**, and **IDP** log types, then save.

### 3. Allow each firewall IP in Wazuh

Add one `<allowed-ips>` line per firewall inside the `<remote>` block (e.g. `10.0.0.1/32`, `10.0.1.1/32`, …), then restart `wazuh-manager`.

### 4. Verify raw logs are arriving

```bash
sudo tcpdump -i eth0 src FIREWALL_IP and port 5514 -nn -A -c 5
```

Example packet:

```
<133>device_name="SFW" timestamp="2026-06-03T11:32:45+0100" device_model="SFVH" ... log_component="CLI" log_subtype="Admin" status="Failed" severity="Notice" user_name="bdsm" src_ip="198.51.100.23" message="User 'bdsm' failed to login from '198.51.100.23' using ssh because of wrong credentials"
```

### 5. Install the decoder and test it

Copy the decoder into `local_decoder.xml`, then:

```bash
echo '<133>device_name="SFW" ... user_name="bdsm" src_ip="198.51.100.23" message="..."' | sudo /var/ossec/bin/wazuh-logtest
```

Expect Phase 2 to show `name: 'sophos-xgs'`, `dstuser: 'bdsm'`, `srcip: '198.51.100.23'`. If you get *No decoder matched*, confirm `device_name="` appears in the log and the prematch saved correctly.

### 6. Install the rules and test them

Copy the rules into `local_rules.xml` and run `wazuh-logtest` against each line in [`samples/test-logs.txt`](samples/test-logs.txt).

| Rule | Level | Detects |
|---|---|---|
| 110100 | 3 | Any Sophos XGS event (base) |
| 110101 | 8 | Admin configuration change |
| 110102 | 10 | Failed admin action |
| 110103 | 3 | SSL VPN login |
| 110104 | 6 | IPSec failure |
| 110105 | 6 | IPSec tunnel expired/timeout |
| 110106 | 8 | Authentication failure |
| 110107 | 10 | Brute force (5 failures / 60 s) |
| 110108 | 3 | Other successful logins |

> **Rule ordering matters.** When several rules share the same `if_sid` parent, Wazuh evaluates the lowest ID first. Specific rules (110101, 110103) therefore have lower IDs than the catch-all (110108), and `type="pcre2"` lets multiple conditions be matched in one expression so the generic rule doesn't fire first.

### 7. Restart and watch live alerts

```bash
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -E "1101(0[1-8])"
```

Example:

```
Rule: 110103 (level 3) -> 'Sophos XGS: SSL VPN login by john.doe from 203.0.113.10'
Rule: 110106 (level 8) -> 'Sophos XGS: Authentication failure for user john.doe from 203.0.113.10'
```

### 8. Verify multiple firewalls

Count alerts per firewall source to confirm all branches are reporting:

```bash
sudo grep -B2 "Rule: 1101" /var/ossec/logs/alerts/alerts.log | grep "\->" | awk '{print $NF}' | sort | uniq -c | sort -rn
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Logs arrive, no decoder match | Check raw logs with `tcpdump`; confirm `device_name="` is present; debug with `wazuh-logtest` |
| Wrong rule fires | Lowest rule ID wins among siblings; combine conditions with `type="pcre2"`; use `wazuh-logtest -v` |
| Firewall traffic dropped | Add the firewall IP to `<allowed-ips>` and restart `wazuh-manager` |
| User/IP empty in alert text | Extract `user_name` and `src_ip` in the same decoder regex (both orderings are included) |

## Ideas to extend

- Add `<same_source_ip />` to rule 110107 so brute force is counted per source IP rather than across all sources
- Add IDP/IPS and web-filter rules (the firewall already forwards these log types)
- Map rules to MITRE ATT&CK (e.g. T1110 Brute Force for 110107)
