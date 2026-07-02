#!/usr/bin/env python3
"""
cloud_dataplane.py - data-plane / SaaS exfiltration detection.

Where cloud_controlplane.py analyzes MANAGEMENT events (who changed what), this analyzes DATA
events (who READ how much): bulk object reads from cloud object storage, cross-account object
copies, and SaaS mass downloads / mailbox exports. These are the Collection + Exfiltration end
of the kill chain - T1530 (Data from Cloud Storage), T1537 (Transfer Data to Cloud Account),
T1114 (Email Collection), T1213 (Data from Information Repositories), T1567 (Exfiltration Over
Web Service).

FP discipline (matches the toolkit philosophy - downgrade, never blind): bulk reads by an
automation identity (service account / assumed role) are routine (ETL, backup, analytics), so on
their own they are Indeterminate ("verify"). The same volume by a HUMAN principal, any
cross-account object copy, and any mailbox export are Likely True Positive. A below-threshold
read simply does not fire - it is not suppressed, there is just no signal yet.
"""
import json

from cloud_findings import finding

# Per-principal object-read volume thresholds within the collection window.
_GET_HIGH = 200     # bulk read at exfiltration scale
_GET_MED = 50       # elevated read worth verifying
_BUCKET_SPREAD = 5  # reading across this many buckets is itself anomalous

_S3_READ = {"GetObject", "SelectObjectContent", "GetObjectTorrent"}
_S3_COPY = {"CopyObject", "UploadPartCopy"}
_M365_DOWNLOAD = {"filedownloaded", "filesyncdownloadedfull", "filesyncdownloadedpartial"}
_M365_MAIL_EXPORT = {"new-mailboxexportrequest", "export mailbox", "new-complianceSearchAction"}


def _records(data, *list_keys):
    """Yield event records from a raw list, a {key:[...]} wrapper, or CloudTrail lookup-events
    output ({"Events":[{"CloudTrailEvent":"<json>"}]}). Format-agnostic across providers."""
    if isinstance(data, dict):
        events = None
        for k in ("Events", "Records", "events", "value", "entries", *list_keys):
            if isinstance(data.get(k), list):
                events = data[k]
                break
        events = events if events is not None else []
    elif isinstance(data, list):
        events = data
    else:
        events = []
    for e in events:
        if not isinstance(e, dict):
            continue
        # CloudTrail lookup-events wrapper: {"CloudTrailEvent": "<json>"}.
        cte = e.get("CloudTrailEvent")
        if isinstance(cte, str):
            try:
                yield json.loads(cte)
                continue
            except Exception:
                pass
        # CloudWatch Logs filter-log-events wrapper: {"message": "<json>"} (real S3 data-event sink).
        msg = e.get("message")
        if isinstance(msg, str):
            try:
                yield json.loads(msg)
                continue
            except Exception:
                pass
        yield e


def _get(rec, *names):
    """Case-insensitive field fetch across mixed API casing."""
    if not isinstance(rec, dict):
        return None
    for n in names:
        if n in rec:
            return rec[n]
    low = {k.lower(): v for k, v in rec.items()}
    for n in names:
        if n.lower() in low:
            return low[n.lower()]
    return None


def _aws_is_human(principal_type):
    """AWS userIdentity.type: IAMUser/Root are humans; AssumedRole/AWSService/AWSAccount are
    automation. Unknown -> automation (conservative: we only ESCALATE on human, so treating an
    unknown as automation avoids over-escalating into a false positive)."""
    return str(principal_type or "").lower() in ("iamuser", "root")


def _emit_bulk(out, actor, human, n, spread, ips, store, mitre):
    """Shared bulk-read tiering: human bulk reader / very high volume / wide bucket spread ->
    Likely TP; otherwise Indeterminate (verify). Below _GET_MED never reaches here."""
    strong = (human and n >= _GET_MED) or n >= _GET_HIGH or spread >= _BUCKET_SPREAD
    verdict = "Likely True Positive" if strong else "Indeterminate"
    who = "human user" if human else "role/service account"
    ip_list = sorted(i for i in ips if i)
    ip_str = ", ".join(ip_list[:3]) + ("…" if len(ip_list) > 3 else "")
    out.append(finding(
        "Cloud Data Exfiltration", actor,
        f"{store} bulk object read: {n} object read(s) across {spread} bucket(s) by {who} "
        f"{actor}{f' from {ip_str}' if ip_str else ''} - possible data collection/exfiltration",
        mitre, verdict, "High" if strong else "Low"))


def normalize_s3_data_events(data):
    """AWS S3 data events (CloudTrail data-event records) -> bulk-read + cross-account-copy exfil.

    Data events are not returned by cloudtrail lookup-events; they are collected from the trail's
    data-event log group (see collect/aws.sh). Accepts CloudWatch-wrapped or raw CloudTrail records."""
    out = []
    reads = {}   # actor -> {n, buckets:set, ips:set, human:bool}
    for rec in _records(data):
        name = _get(rec, "eventName") or ""
        if not name:
            continue
        uid = _get(rec, "userIdentity") or {}
        ptype = uid.get("type") if isinstance(uid, dict) else ""
        actor = "unknown"
        if isinstance(uid, dict):
            actor = uid.get("userName") or uid.get("arn") or uid.get("principalId") or "unknown"
        ip = _get(rec, "sourceIPAddress") or ""
        params = _get(rec, "requestParameters") or {}
        bucket = params.get("bucketName") if isinstance(params, dict) else None

        # Cross-account / external object copy = staged transfer to attacker-controlled storage.
        if name in _S3_COPY:
            src = params.get("copySource") if isinstance(params, dict) else None
            out.append(finding(
                "Cloud Data Exfiltration", f"{name}:{bucket or '?'}",
                f"S3 {name} by {actor} from {ip or '?'} (copySource={src}) - object copy, "
                f"possible transfer to an attacker-controlled bucket",
                "T1537 (Transfer Data to Cloud Account)", "Likely True Positive", "High"))
            continue

        if name in _S3_READ:
            agg = reads.setdefault(actor, {"n": 0, "buckets": set(), "ips": set(),
                                           "human": _aws_is_human(ptype)})
            agg["n"] += 1
            if bucket:
                agg["buckets"].add(bucket)
            if ip:
                agg["ips"].add(ip)

    for actor, a in reads.items():
        if a["n"] >= _GET_MED:
            _emit_bulk(out, actor, a["human"], a["n"], len(a["buckets"]), a["ips"],
                       "S3", "T1530 (Data from Cloud Storage)")
    return out


def normalize_gcp_data_access(data):
    """GCP Cloud Audit DATA_ACCESS logs -> bulk object reads (storage.objects.get / list).

    Reads the same gcp_audit_log.json the control-plane analyzer uses (the data-access stream is
    already collected there); keys only on the storage read methods."""
    out = []
    reads = {}
    entries = data if isinstance(data, list) else (data or {}).get("entries", []) \
        if isinstance(data, dict) else []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        proto = entry.get("protoPayload", entry)
        if not isinstance(proto, dict):
            continue
        method = str(proto.get("methodName", ""))
        if "storage.objects.get" not in method and "storage.objects.list" not in method:
            continue
        auth = proto.get("authenticationInfo", {})
        actor = auth.get("principalEmail", "unknown") if isinstance(auth, dict) else "unknown"
        res = str(proto.get("resourceName", ""))
        bucket = res.split("/objects/")[0] if "/objects/" in res else res
        agg = reads.setdefault(actor, {"n": 0, "buckets": set(), "ips": set(),
                                       "human": not str(actor).endswith(".gserviceaccount.com")})
        agg["n"] += 1
        if bucket:
            agg["buckets"].add(bucket)
    for actor, a in reads.items():
        if a["n"] >= _GET_MED:
            _emit_bulk(out, actor, a["human"], a["n"], len(a["buckets"]), a["ips"],
                       "GCS", "T1530 (Data from Cloud Storage)")
    return out


def normalize_m365_audit(data):
    """M365 unified audit log -> SaaS mass download (SharePoint/OneDrive) + mailbox export.

    Mailbox export and compliance-search export are always Likely TP (bulk mailbox extraction);
    file downloads tier by volume like object reads."""
    out = []
    downloads = {}   # user -> count
    for r in _records(data):
        op = str(_get(r, "Operation", "operation") or "").strip().lower()
        user = _get(r, "UserId", "userId", "userPrincipalName") or "unknown"
        if not op:
            continue
        if op in _M365_MAIL_EXPORT:
            out.append(finding(
                "Cloud Data Exfiltration", user,
                f"M365: mailbox/compliance export request by {user} - bulk mailbox extraction",
                "T1114.002 (Email Collection: Remote Email Collection)",
                "Likely True Positive", "High"))
            continue
        if op in _M365_DOWNLOAD:
            downloads[user] = downloads.get(user, 0) + 1
    for user, n in downloads.items():
        if n < _GET_MED:
            continue
        strong = n >= _GET_HIGH
        out.append(finding(
            "Cloud Data Exfiltration", user,
            f"M365: {n} SharePoint/OneDrive file download(s) by {user} - bulk download, "
            f"possible collection/exfiltration",
            "T1213 (Data from Information Repositories), T1567 (Exfiltration Over Web Service)",
            "Likely True Positive" if strong else "Indeterminate", "High" if strong else "Low"))
    return out
