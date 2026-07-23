import pytest

from src.normalization.cloudtrail import (
    normalize_cloudtrail_event,
    normalize_cloudtrail_records,
)


def build_console_login_event() -> dict:
    return {
        "eventVersion": "1.10",
        "eventTime": "2026-07-18T15:30:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.168.119.131",
        "recipientAccountId": "123456789012",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/admin-user",
            "accountId": "123456789012",
            "userName": "admin-user",
        },
        "responseElements": {
            "ConsoleLogin": "Failure",
        },
    }


def test_console_login_normalization():
    raw_event = build_console_login_event()
    event = normalize_cloudtrail_event(raw_event)

    assert event.source_type == "cloud"
    assert event.source_product == "cloudtrail"
    assert event.category == "authentication"
    assert event.action == "ConsoleLogin"
    assert event.outcome == "failure"
    assert event.username == "admin-user"
    assert event.source_ip == "192.168.119.131"
    assert event.cloud_provider == "aws"
    assert event.cloud_account_id == "123456789012"
    assert event.cloud_region == "us-east-1"
    assert event.severity == "informational"


def test_cloudtrail_error_code_means_failure():
    raw_event = {
        "eventTime": "2026-07-18T16:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.168.119.131",
        "errorCode": "AccessDenied",
        "errorMessage": "User is not authorized.",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "student-user",
        },
    }

    event = normalize_cloudtrail_event(raw_event)

    assert event.outcome == "failure"
    assert event.category == "identity_and_access"


def test_successful_api_call_without_error():
    raw_event = {
        "eventTime": "2026-07-18T16:10:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "192.168.119.131",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "admin-user",
        },
    }

    event = normalize_cloudtrail_event(raw_event)

    assert event.outcome == "success"
    assert event.category == "identity_and_access"


def test_assumed_role_identity_is_extracted():
    raw_event = {
        "eventTime": "2026-07-18T16:20:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "AuthorizeSecurityGroupIngress",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.10",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": "AROAEXAMPLE:session-name",
            "accountId": "123456789012",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "userName": "NetworkAdministrator",
                    "arn": (
                        "arn:aws:iam::123456789012:"
                        "role/NetworkAdministrator"
                    ),
                    "accountId": "123456789012",
                }
            },
        },
    }

    event = normalize_cloudtrail_event(raw_event)

    assert event.username == "NetworkAdministrator"
    assert event.user_type == "AssumedRole"
    assert event.category == "network_configuration"
    assert event.cloud_account_id == "123456789012"


def test_raw_event_is_copied():
    raw_event = build_console_login_event()
    event = normalize_cloudtrail_event(raw_event)

    raw_event["eventName"] = "ChangedAfterNormalization"

    assert event.raw_event["eventName"] == "ConsoleLogin"


def test_multiple_records_are_normalized():
    first_record = build_console_login_event()
    second_record = build_console_login_event()
    second_record["eventTime"] = "2026-07-18T15:31:00Z"

    events = normalize_cloudtrail_records(
        [first_record, second_record]
    )

    assert len(events) == 2
    assert events[0].event_id != events[1].event_id


def test_missing_event_time_is_rejected():
    raw_event = {
        "eventName": "ConsoleLogin",
    }

    with pytest.raises(
        ValueError,
        match="CloudTrail eventTime is required",
    ):
        normalize_cloudtrail_event(raw_event)


def test_missing_event_name_is_rejected():
    raw_event = {
        "eventTime": "2026-07-18T15:30:00Z",
    }

    with pytest.raises(
        ValueError,
        match="CloudTrail eventName is required",
    ):
        normalize_cloudtrail_event(raw_event)


def test_non_dictionary_event_is_rejected():
    with pytest.raises(
        TypeError,
        match="CloudTrail event must be a dictionary",
    ):
        normalize_cloudtrail_event("invalid")  # type: ignore[arg-type]


def test_records_must_be_list():
    with pytest.raises(
        TypeError,
        match="CloudTrail records must be provided as a list",
    ):
        normalize_cloudtrail_records({})  # type: ignore[arg-type]
