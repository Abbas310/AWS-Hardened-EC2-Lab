# AWS Hardened EC2 Linux Server

## Project Overview

This project demonstrates deploying and hardening an Ubuntu Linux server on AWS EC2 using industry-standard security best practices.

The objective is to establish a secure baseline configuration that reduces attack surface, prevents common compromise techniques, and enables basic threat detection and response.

---

## Architecture

- AWS EC2 (Ubuntu 22.04 LTS)
- SSH key-based authentication
- Non-root administrative user
- Host-based firewall (UFW)
- Brute-force protection (Fail2Ban)
- Automatic security updates
- Log monitoring and alerting (CloudWatch / CloudTrail)

---

## Hardening Steps

- Deployed Ubuntu EC2 instance
- Applied system updates and security patches
- Created non-root administrative user
- Disabled root SSH login
- Disabled password authentication
- Enforced SSH key-only access
- Configured UFW firewall
- Installed and configured Fail2Ban
- Enabled unattended security upgrades

---

## Security Monitoring & Incident Response

- Monitored authentication logs for failed SSH attempts
- Created alerting for suspicious login activity (e.g., multiple failed SSH attempts)
- Detected repeated brute-force login attempts from external IP
- Responded by blocking malicious IP using UFW firewall
- Validated mitigation by stopping further unauthorized access attempts

---

## Validation

Evidence provided in the screenshots folder:

- Successful SSH login using non-root user
- Firewall active and enforcing rules
- Fail2Ban actively monitoring and blocking attempts
- Automatic updates enabled
- SSH hardening configurations applied
- Detection of failed SSH login attempts in logs
- Firewall rule applied to block malicious IP

---

## Automated Security Enforcement

- Developed AWS Lambda function to enforce secure network configurations
- Automatically detected and removed insecure inbound rules (e.g., 0.0.0.0/0 exposure)
- Integrated with AWS event/logging mechanisms for trigger-based remediation
- Reduced risk of unintended public exposure of services

---

## Security Rationale

- Non-root access prevents direct privilege escalation
- Key-based authentication mitigates brute-force attacks
- Firewall restricts exposed network services
- Fail2Ban provides automated protection against repeated login attempts
- Monitoring and alerting enable detection of suspicious activity
- Manual response (IP blocking) demonstrates incident mitigation
- Automatic updates reduce exposure to known vulnerabilities
- Automated remediation enforces security policies and reduces human error
  
---

## Lessons Learned

- Importance of least privilege access
- Value of layered security controls (defense in depth)
- Basics of Linux server hardening
- Fundamentals of cloud VM security
- Introduction to security monitoring and incident response
