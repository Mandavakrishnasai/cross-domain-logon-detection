#  Cross-Domain Logon Detection in Splunk

This project detects suspicious logon activity in Windows environments using Splunk. It looks for cases where a user logs into a host from a domain that doesn’t match the domain the host belongs to. This can be a sign of credential misuse, lateral movement, or misconfiguration in the environment.

---

##  What This Detection Does

In most organizations, systems are joined to a specific domain, and users should typically log in from accounts that belong to the same domain. If someone logs into a machine from a different domain, it might indicate:
- Credential abuse or unauthorized access  
- Lateral movement across domain boundaries  
- Misconfigured service accounts or policies  

This SPL query correlates **Windows EventCode 4624 (logon events)** with a lookup table that maps each host to its expected domain.

---

##  SPL Query (Core Detection Logic)

```spl
index=wineventlog EventCode=4624
| eval ComputerName=trim(lower(ComputerName))
| lookup asset_lookup host AS ComputerName OUTPUT domain AS asset_domain
| eval Logon_Domain=lower(Logon_Domain), asset_domain=lower(asset_domain)
| where Logon_Domain != asset_domain
| search NOT Account_Name IN ("svc_web", "svc_backup")
| stats count by Account_Name, Logon_Domain, ComputerName, asset_domain
| sort -count
| rename Account_Name AS "User", Logon_Domain AS "User Domain", ComputerName AS "Target Host", asset_domain AS "Host Domain", count AS "Logon Count"
```

---

## Project Files

| File Name                    | Purpose                                                 |
| ---------------------------- | ------------------------------------------------------- |
| `cross_domain_detection.spl` | SPL query used to detect cross-domain logons            |
| `asset_lookup.csv`           | Maps hostnames to their expected domain                 |
| `wineventlog_4624.csv`       | Sample 4624 logs for testing (optional synthetic data)  |
| `wineventlog_4768.csv`       | Sample Kerberos logs (optional support data)            |
| `cross_domain_results.csv`   | Sample output showing flagged logons                    |

---

## How to Use This

1. **Upload the Lookup:**
   - Go to Splunk → `Settings > Lookups > Lookup table files`
   - Upload `asset_lookup.csv`
   - Create a lookup definition called `asset_lookup` with:
     - Key: `host`
     - Output field: `domain`

2. **Ingest Sample Data (if needed):**
   - Use `Add Data` to ingest `wineventlog_4624.csv`
   - Assign sourcetype: `WinEventLog:Security`
   - Assign to index: `wineventlog`

3. **Run the SPL Query:**
   - Copy-paste the SPL from `cross_domain_detection.spl` into Splunk search
   - You should see logons where the user's domain doesn’t match the host domain

---

##  Why This Is Useful

| Field         | Description                                  |
| ------------- | -------------------------------------------- |
| User          | Who logged in                                |
| User Domain   | Domain the user belongs to                   |
| Target Host   | The machine that was logged into             |
| Host Domain   | What domain the machine is expected to be in |
| Logon Count   | Number of such logons                        |

This detection can help identify unusual patterns like:
- Admins logging into machines outside their usual scope
- Credential misuse between domains
- Shadow IT or unapproved trust relationships

---

##  ATT&CK Mapping (Rough)

| Tactic           | Technique                                                                                     |
| ---------------- | --------------------------------------------------------------------------------------------- |
| Lateral Movement | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| Defense Evasion  | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)                          |

---

## Notes

- This detection uses Windows EventCode 4624
- `Account_Name`, `Logon_Domain`, and `ComputerName` are default fields from those logs
- Make sure `asset_lookup.csv` has `host` and `domain` columns
- Excludes some known service accounts from alerting

---

##  About This Project

This was built as part of a SOC detection engineering project to explore how to enrich logon data with asset metadata and detect misused credentials across domains. Built using Splunk and tested with synthetic Windows event logs.

