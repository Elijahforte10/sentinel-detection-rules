# Sentinel Detection Rules (MITRE ATT&CK-Mapped)

KQL analytics rules for Microsoft Sentinel, each mapped to a specific MITRE
ATT&CK technique. The focus is identity-layer attacks against Entra ID — the
detections that matter most for a cloud-identity-focused SOC.

## Rules → ATT&CK mapping

| Rule | Technique | Tactic | Data source |
|---|---|---|---|
| `password-spray.kql` | T1110.003 Password Spraying | Credential Access | SigninLogs |
| `bruteforce-then-success.kql` | T1110 → T1078 | Credential Access → Initial Access | SigninLogs |
| `legacy-auth-signin.kql` | T1078.004 Cloud Accounts | Defense Evasion / Persistence | SigninLogs |
| `privileged-role-assignment.kql` | T1098.003 Additional Cloud Roles | Persistence / Priv-Esc | AuditLogs |

## Using these

1. In Sentinel, go to **Analytics → Create → Scheduled query rule**.
2. Paste the KQL from a rule file.
3. Set the schedule/lookback to match the window in the query comment
   (e.g. 1h for spray, 6h for the brute-force join).
4. Under **Entity mapping**, map `UserPrincipalName` → Account and
   `IPAddress` → IP so incidents are investigable.
5. Tag the rule with the technique ID from the table above so your coverage
   shows up correctly in the MITRE ATT&CK blade.

## Tuning

Every rule has thresholds called out at the top (distinct-user count, failure
count, time windows). Baseline your own environment first — a busy tenant may
need higher thresholds to cut false positives, a small one lower. The comments
in each file explain the detection logic so you can defend each choice.

## Coverage notes

These cover the most common identity attack path: spray/brute-force → valid
account → privilege escalation/persistence. Natural next additions: impossible-
travel (T1078), MFA-fatigue / repeated push (T1621), and OAuth consent grant
abuse (T1528).
