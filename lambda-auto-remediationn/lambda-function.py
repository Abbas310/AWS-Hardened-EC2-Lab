import os
import json
import boto3

ec2 = boto3.client("ec2")

TARGET_SG_ID = os.environ.get("TARGET_SG_ID", "").strip()
SAFE_SSH_CIDR = os.environ.get("SAFE_SSH_CIDR", "").strip()  # e.g., "203.0.113.10/32"
RESTRICT_BACK = os.environ.get("RESTRICT_BACK", "false").lower() == "true"


def lambda_handler(event, context):
    # EventBridge delivers a CloudTrail-like event envelope
    detail = event.get("detail", {})
    event_name = detail.get("eventName")

    # We only care about ingress authorize calls
    if event_name != "AuthorizeSecurityGroupIngress":
        return _ok("Ignored: not AuthorizeSecurityGroupIngress", event)

    req = detail.get("requestParameters", {})
    sg_id = req.get("groupId") or req.get("groupId".lower())

    if not sg_id:
        return _ok("Ignored: no groupId in requestParameters", event)

    if sg_id != TARGET_SG_ID:
        return _ok(f"Ignored: groupId {sg_id} != TARGET_SG_ID", event)

    ip_permissions = req.get("ipPermissions", {}).get("items", [])
    if not ip_permissions:
        return _ok("Ignored: no ipPermissions.items present", event)

    # Find and remove any rule that opens TCP/22 to 0.0.0.0/0 (or ::/0 optionally)
    removed = []
    for perm in ip_permissions:
        ip_proto = perm.get("ipProtocol")
        from_port = perm.get("fromPort")
        to_port = perm.get("toPort")

        # Only SSH on TCP 22
        if ip_proto not in ("tcp", "6"):
            continue
        if from_port != 22 or to_port != 22:
            continue

        ipv4_ranges = perm.get("ipRanges", {}).get("items", [])
        # Optional: also handle IPv6 if you ever enable it:
        ipv6_ranges = perm.get("ipv6Ranges", {}).get("items", [])

        # Identify bad ranges
        bad_ipv4 = [r.get("cidrIp") for r in ipv4_ranges if r.get("cidrIp") == "0.0.0.0/0"]
        bad_ipv6 = [r.get("cidrIpv6") for r in ipv6_ranges if r.get("cidrIpv6") == "::/0"]

        if not bad_ipv4 and not bad_ipv6:
            continue

        # Build permission object for revoke
        revoke_perm = {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
        }
        if bad_ipv4:
            revoke_perm["IpRanges"] = [{"CidrIp": "0.0.0.0/0"}]
        if bad_ipv6:
            revoke_perm["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]

        ec2.revoke_security_group_ingress(
            GroupId=TARGET_SG_ID,
            IpPermissions=[revoke_perm],
        )
        removed.append(revoke_perm)

    # Optionally re-add a safe SSH rule for your IP
    readded = None
    if removed and RESTRICT_BACK and SAFE_SSH_CIDR:
        # Ensure your SAFE_SSH_CIDR exists
        safe_perm = {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": SAFE_SSH_CIDR, "Description": "Safe SSH (auto-restored)"}],
        }
        try:
            ec2.authorize_security_group_ingress(
                GroupId=TARGET_SG_ID,
                IpPermissions=[safe_perm],
            )
            readded = safe_perm
        except Exception as e:
            # If it already exists, AWS may throw InvalidPermission.Duplicate; that's fine.
            readded = {"attempted": safe_perm, "note": f"Could not add (maybe exists): {str(e)}"}

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Auto-remediation evaluated",
                "target_sg": TARGET_SG_ID,
                "removed": removed,
                "readded": readded,
            },
            indent=2,
        ),
    }


def _ok(msg, event):
    return {"statusCode": 200, "body": json.dumps({"message": msg}, indent=2)}
