"""AWS CloudTrail normalizer for SOC Copilot Version 2."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from src.normalization.schema import NormalizedEvent


AUTHENTICATION_ACTIONS = {
    "ConsoleLogin",
    "AssumeRole",
    "GetFederationToken",
    "GetSessionToken",
}

IAM_ACTIONS = {
    "CreateAccessKey",
    "DeleteAccessKey",
    "UpdateAccessKey",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "PutRolePolicy",
    "CreateUser",
    "DeleteUser",
    "CreateRole",
    "DeleteRole",
    "AddUserToGroup",
    "RemoveUserFromGroup",
    "UpdateAssumeRolePolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "DeleteLoginProfile",
    "EnableMFADevice",
    "DeactivateMFADevice",
    "DeleteVirtualMFADevice",
}

LOGGING_ACTIONS = {
    "StopLogging",
    "StartLogging",
    "DeleteTrail",
    "CreateTrail",
    "UpdateTrail",
    "PutEventSelectors",
    "PutInsightSelectors",
}

NETWORK_ACTIONS = {
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "RevokeSecurityGroupEgress",
    "CreateSecurityGroup",
    "DeleteSecurityGroup",
    "CreateNetworkAcl",
    "DeleteNetworkAcl",
}

STORAGE_ACTIONS = {
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "PutBucketAcl",
    "PutPublicAccessBlock",
    "DeletePublicAccessBlock",
}


def _get_session_issuer(user_identity: dict[str, Any]) -> dict[str, Any]:
    """Return the identity that issued an assumed-role session."""

    session_context = user_identity.get("sessionContext", {})
    session_issuer = session_context.get("sessionIssuer", {})

    return session_issuer if isinstance(session_issuer, dict) else {}


def _extract_username(user_identity: dict[str, Any]) -> str | None:
    """Extract the most useful human-readable AWS identity."""

    session_issuer = _get_session_issuer(user_identity)

    return (
        user_identity.get("userName")
        or session_issuer.get("userName")
        or user_identity.get("arn")
        or session_issuer.get("arn")
        or user_identity.get("principalId")
    )


def _extract_user_arn(user_identity: dict[str, Any]) -> str | None:
    """Extract the direct or session-issuer ARN."""

    session_issuer = _get_session_issuer(user_identity)

    return user_identity.get("arn") or session_issuer.get("arn")


def _extract_account_id(
    event: dict[str, Any],
    user_identity: dict[str, Any],
) -> str | None:
    """Extract the AWS account receiving or producing the event."""

    session_issuer = _get_session_issuer(user_identity)

    return (
        event.get("recipientAccountId")
        or user_identity.get("accountId")
        or session_issuer.get("accountId")
    )


def _infer_outcome(event: dict[str, Any]) -> str:
    """Infer whether an AWS API action succeeded or failed."""

    if event.get("errorCode") or event.get("errorMessage"):
        return "failure"

    response_elements = event.get("responseElements")

    if isinstance(response_elements, dict):
        console_login_result = response_elements.get("ConsoleLogin")

        if isinstance(console_login_result, str):
            normalized_result = console_login_result.strip().lower()

            if normalized_result == "success":
                return "success"

            if normalized_result == "failure":
                return "failure"

    # CloudTrail management events without an error generally represent
    # successful API calls.
    return "success"


def _infer_category(action: str) -> str:
    """Map an AWS action into a common security-event category."""

    if action in AUTHENTICATION_ACTIONS:
        return "authentication"

    if action in IAM_ACTIONS:
        return "identity_and_access"

    if action in LOGGING_ACTIONS:
        return "logging"

    if action in NETWORK_ACTIONS:
        return "network_configuration"

    if action in STORAGE_ACTIONS:
        return "cloud_storage"

    return "cloud_activity"


def normalize_cloudtrail_event(event: dict[str, Any]) -> NormalizedEvent:
    """Convert one raw CloudTrail record into a NormalizedEvent."""

    if not isinstance(event, dict):
        raise TypeError("CloudTrail event must be a dictionary")

    timestamp = event.get("eventTime")
    action = event.get("eventName")
    event_source = event.get("eventSource")

    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError("CloudTrail eventTime is required")

    if not isinstance(action, str) or not action.strip():
        raise ValueError("CloudTrail eventName is required")

    user_identity = event.get("userIdentity", {})

    if not isinstance(user_identity, dict):
        user_identity = {}

    category = _infer_category(action)

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="cloud",
        source_product="cloudtrail",
        category=category,
        action=action,
        outcome=_infer_outcome(event),

        # Raw telemetry is informational. Detection rules will determine
        # whether the activity should become a higher-severity alert.
        severity="informational",

        username=_extract_username(user_identity),
        user_id=user_identity.get("principalId"),
        user_type=user_identity.get("type"),
        user_arn=_extract_user_arn(user_identity),

        source_ip=event.get("sourceIPAddress"),

        cloud_provider="aws",
        cloud_account_id=_extract_account_id(event, user_identity),
        cloud_region=event.get("awsRegion"),

        message=(
            f"AWS CloudTrail event {action}"
            + (f" from {event_source}" if event_source else "")
        ),

        tags=[
            "aws",
            "cloudtrail",
            category,
        ],

        # Keep a separate copy so later modifications to the original
        # dictionary do not change the stored evidence.
        raw_event=deepcopy(event),
    )


def normalize_cloudtrail_records(
    records: list[dict[str, Any]],
) -> list[NormalizedEvent]:
    """Normalize multiple CloudTrail records."""

    if not isinstance(records, list):
        raise TypeError("CloudTrail records must be provided as a list")

    return [
        normalize_cloudtrail_event(event)
        for event in records
    ]
