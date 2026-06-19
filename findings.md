# Investigation Findings

## Incident Summary

Multiple failed SSH login attempts were detected from external IP addresses during log analysis.

## Findings

- IP 45.155.205.233 generated 5 failed login attempts targeting the root account.
- IP 185.220.101.45 generated 3 failed login attempts targeting the admin account.
- IP 103.99.0.122 generated 1 failed login attempt.

## Assessment

The activity is consistent with SSH brute force behavior targeting privileged accounts.

## Impact

No successful compromise was detected in the analyzed logs.

## Recommendations

- Disable direct root SSH login.
- Implement multi-factor authentication (MFA).
- Configure account lockout policies.
- Monitor repeated failed authentication attempts.
- Restrict SSH access to trusted IP addresses.

## Analyst Notes

This investigation demonstrates the identification of brute force activity through Linux SSH authentication log analysis and automated threat detection using Python.
