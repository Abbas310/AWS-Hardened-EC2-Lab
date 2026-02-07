#AWS Hardened EC2 Linux Server
#Project Overview

This project demonstrates deploying and hardening an Ubuntu Linux server on AWS EC2 using industry-standard security best practices.

The goal is to establish a secure baseline configuration that reduces attack surface and prevents common compromise techniques.

#Architecture

>AWS EC2 (Ubuntu 22.04 LTS)
>SSH key-based authentication
>Non-root administrative user
>Host-based firewall (UFW)
>Brute-force protection (Fail2Ban)
>Automatic security updates

#Hardening Steps

>Deployed Ubuntu EC2 instance
>Applied system updates and patches
>Created non-root administrative user
>Disabled root SSH login
>Disabled password authentication
>Enabled SSH key-only access
>Configured UFW firewall
>Installed and configured Fail2Ban
>Enabled unattended security upgrades

#Validation

>Evidence of the following is provided in the screenshots folder:
>Successful SSH login as non-root user
>Firewall active and enforcing rules
>Fail2Ban running
>Automatic updates enabled
>SSH hardening settings applied

#Security Rationale

>Non-root access prevents direct privilege escalation
>Key-based authentication mitigates credential brute-force attacks
>Firewall restricts exposed network services
>Fail2Ban blocks repeated authentication attempts
>Automatic updates reduce exposure to known vulnerabilities

#Lessons Learned

>Importance of least privilege
>Value of layered security controls
>Basic Linux hardening techniques
>Cloud VM security fundamentals