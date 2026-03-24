# Lambda Auto-Remediation (Security Group SSH Enforcement)

AWS Lambda function that enforces secure EC2 security group configurations by preventing public SSH exposure.

## Overview

Triggered by EventBridge (CloudTrail events) when a security group ingress rule is created. The function detects and removes any rule allowing SSH access (TCP/22) from `0.0.0.0/0` or `::/0`.

Optionally restores SSH access restricted to a trusted IP range.

## Functionality

- Monitors `AuthorizeSecurityGroupIngress` events  
- Detects SSH rules exposed to the public (`0.0.0.0/0`, `::/0`)  
- Automatically revokes insecure rules  
- Optionally re-applies SSH access for a trusted CIDR  
- Applies only to a specified target security group  

## Configuration

- `TARGET_SG_ID` – Security group to monitor  
- `SAFE_SSH_CIDR` – Trusted IP range (e.g., `203.0.113.10/32`)  
- `RESTRICT_BACK` – Enable/disable re-applying restricted SSH access  

## Security Objective

Prevent accidental public exposure of EC2 instances and enforce least-privilege network access through automated remediation.