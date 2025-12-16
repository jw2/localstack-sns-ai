import base64
import json
from uuid import uuid4

from botocore.utils import InvalidArnException

from localstack.aws.api import CommonServiceException
from localstack.aws.api.sns import (
    InvalidParameterException,
    InvalidParameterValueException,
    MessageAttributeMap,
    TagList,
)
from localstack.services.sns import constants as sns_constants
from localstack.services.sns.models import SnsStore
from localstack.utils.aws.arns import ArnData, parse_arn
from localstack.utils.strings import short_uid, to_bytes, to_str


def parse_and_validate_topic_arn(topic_arn: str | None) -> ArnData:
    return _parse_and_validate_arn(topic_arn, "Topic")


def parse_and_validate_platform_application_arn(platform_application_arn: str | None) -> ArnData:
    return _parse_and_validate_arn(platform_application_arn, "PlatformApplication")


def _parse_and_validate_arn(arn: str | None, resource_type: str) -> ArnData:
    arn = arn or ""
    try:
        return parse_arn(arn)
    except InvalidArnException:
        count = len(arn.split(":"))
        raise InvalidParameterException(
            f"Invalid parameter: {resource_type}Arn Reason: An ARN must have at least 6 elements, not {count}"
        )


def create_subscription_arn(topic_arn: str) -> str:
    # This is the format of a Subscription ARN
    # arn:aws:sns:us-west-2:123456789012:my-topic:8a21d249-4329-4871-acc6-7be709c6ea7f
    return f"{topic_arn}:{uuid4()}"


def create_platform_endpoint_arn(platform_application_arn: str) -> str:
    # This is the format of an Endpoint Arn
    # arn:aws:sns:us-west-2:1234567890:endpoint/GCM/MyApplication/12345678-abcd-9012-efgh-345678901234
    return f"{platform_application_arn.replace('app', 'endpoint', 1)}/{uuid4()}"


def encode_subscription_token_with_region(region: str) -> str:
    """
    Create a 64 characters Subscription Token with the region encoded
    :param region:
    :return: a subscription token with the region encoded
    """
    return ((region.encode() + b"/").hex() + short_uid() * 8)[:64]


def get_region_from_subscription_token(token: str) -> str:
    """
    Try to decode and return the region from a subscription token
    :param token:
    :return: the region if able to decode it
    :raises: InvalidParameterException if the token is invalid
    """
    try:
        region = token.split("2f", maxsplit=1)[0]
        return bytes.fromhex(region).decode("utf-8")
    except (IndexError, ValueError, TypeError, UnicodeDecodeError):
        raise InvalidParameterException("Invalid parameter: Token")


def get_next_page_token_from_arn(resource_arn: str) -> str:
    return to_str(base64.b64encode(to_bytes(resource_arn)))


def _get_byte_size(payload: str | bytes) -> int:
    # Calculate the real length of the byte object if the object is a string
    return len(to_bytes(payload))


def get_total_publish_size(
    message_body: str, message_attributes: MessageAttributeMap | None
) -> int:
    size = _get_byte_size(message_body)
    if message_attributes:
        # https://docs.aws.amazon.com/sns/latest/dg/sns-message-attributes.html
        # All parts of the message attribute, including name, type, and value, are included in the message size
        # restriction, which is 256 KB.
        # iterate over the Keys and Attributes, adding the length of the Key to the length of all Attributes values
        # (DataType and StringValue or BinaryValue)
        size += sum(
            _get_byte_size(key) + sum(_get_byte_size(attr_value) for attr_value in attr.values())
            for key, attr in message_attributes.items()
        )

    return size


def validate_subscription_attribute(
    attribute_name: str,
    attribute_value: str,
    topic_arn: str,
    endpoint: str,
    is_subscribe_call: bool = False,
) -> None:
    """
    Validate the subscription attribute to be set. See:
    https://docs.aws.amazon.com/sns/latest/api/API_SetSubscriptionAttributes.html
    :param attribute_name: the subscription attribute name, must be in VALID_SUBSCRIPTION_ATTR_NAME
    :param attribute_value: the subscription attribute value
    :param topic_arn: the topic_arn of the subscription, needed to know if it is FIFO
    :param endpoint: the subscription endpoint (like an SQS queue ARN)
    :param is_subscribe_call: the error message is different if called from Subscribe or SetSubscriptionAttributes
    :raises InvalidParameterException
    :return:
    """
    error_prefix = (
        "Invalid parameter: Attributes Reason: " if is_subscribe_call else "Invalid parameter: "
    )
    if attribute_name not in sns_constants.VALID_SUBSCRIPTION_ATTR_NAME:
        raise InvalidParameterException(f"{error_prefix}AttributeName")

    if attribute_name == "FilterPolicy":
        try:
            json.loads(attribute_value or "{}")
        except json.JSONDecodeError:
            raise InvalidParameterException(f"{error_prefix}FilterPolicy: failed to parse JSON.")
    elif attribute_name == "FilterPolicyScope":
        if attribute_value not in ("MessageAttributes", "MessageBody"):
            raise InvalidParameterException(
                f"{error_prefix}FilterPolicyScope: Invalid value [{attribute_value}]. "
                f"Please use either MessageBody or MessageAttributes"
            )
    elif attribute_name == "RawMessageDelivery":
        # TODO: only for SQS and https(s) subs, + firehose
        if attribute_value.lower() not in ("true", "false"):
            raise InvalidParameterException(
                f"{error_prefix}RawMessageDelivery: Invalid value [{attribute_value}]. Must be true or false."
            )

    elif attribute_name == "RedrivePolicy":
        try:
            dlq_target_arn = json.loads(attribute_value).get("deadLetterTargetArn", "")
        except json.JSONDecodeError:
            raise InvalidParameterException(f"{error_prefix}RedrivePolicy: failed to parse JSON.")
        try:
            parsed_arn = parse_arn(dlq_target_arn)
        except InvalidArnException:
            raise InvalidParameterException(
                f"{error_prefix}RedrivePolicy: deadLetterTargetArn is an invalid arn"
            )

        if topic_arn.endswith(".fifo"):
            if endpoint.endswith(".fifo") and (
                not parsed_arn["resource"].endswith(".fifo") or "sqs" not in parsed_arn["service"]
            ):
                raise InvalidParameterException(
                    f"{error_prefix}RedrivePolicy: must use a FIFO queue as DLQ for a FIFO Subscription to a FIFO Topic."
                )


def validate_message_attribute_name(name: str) -> None:
    """
    Validate the message attribute name with the specification of AWS.
    The message attribute name can contain the following characters: A-Z, a-z, 0-9, underscore(_), hyphen(-), and period (.). The name must not start or end with a period, and it should not have successive periods.
    :param name: message attribute name
    :raises InvalidParameterValueException: if the name does not conform to the spec
    """
    if not sns_constants.MSG_ATTR_NAME_REGEX.match(name):
        # find the proper exception
        if name[0] == ".":
            raise InvalidParameterValueException(
                "Invalid message attribute name starting with character '.' was found."
            )
        elif name[-1] == ".":
            raise InvalidParameterValueException(
                "Invalid message attribute name ending with character '.' was found."
            )

        for idx, char in enumerate(name):
            if char not in sns_constants.VALID_MSG_ATTR_NAME_CHARS:
                # change prefix from 0x to #x, without capitalizing the x
                hex_char = "#x" + hex(ord(char)).upper()[2:]
                raise InvalidParameterValueException(
                    f"Invalid non-alphanumeric character '{hex_char}' was found in the message attribute name. Can only include alphanumeric characters, hyphens, underscores, or dots."
                )
            # even if we go negative index, it will be covered by starting/ending with dot
            if char == "." and name[idx - 1] == ".":
                raise InvalidParameterValueException(
                    "Message attribute name can not have successive '.' character."
                )


def validate_message_attributes(
    message_attributes: MessageAttributeMap, position: int | None = None
) -> None:
    """
    Validate the message attributes, and raises an exception if those do not follow AWS validation
    See: https://docs.aws.amazon.com/sns/latest/dg/sns-message-attributes.html
    Regex from: https://stackoverflow.com/questions/40718851/regex-that-does-not-allow-consecutive-dots
    :param message_attributes: the message attributes map for the message
    :param position: given to give the Batch Entry position if coming from `publishBatch`
    :raises: InvalidParameterValueException
    :return: None
    """
    for attr_name, attr in message_attributes.items():
        if len(attr_name) > 256:
            raise InvalidParameterValueException(
                "Length of message attribute name must be less than 256 bytes."
            )
        validate_message_attribute_name(attr_name)
        # `DataType` is a required field for MessageAttributeValue
        if (data_type := attr.get("DataType")) is None:
            if position:
                at = f"publishBatchRequestEntries.{position}.member.messageAttributes.{attr_name}.member.dataType"
            else:
                at = f"messageAttributes.{attr_name}.member.dataType"

            raise CommonServiceException(
                code="ValidationError",
                message=f"1 validation error detected: Value null at '{at}' failed to satisfy constraint: Member must not be null",
                sender_fault=True,
            )

        if data_type not in (
            "String",
            "Number",
            "Binary",
        ) and not sns_constants.ATTR_TYPE_REGEX.match(data_type):
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' has an invalid message attribute type, the set of supported type prefixes is Binary, Number, and String."
            )
        if not any(attr_value.endswith("Value") for attr_value in attr):
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' must contain non-empty message attribute value for message attribute type '{data_type}'."
            )

        value_key_data_type = "Binary" if data_type.startswith("Binary") else "String"
        value_key = f"{value_key_data_type}Value"
        if value_key not in attr:
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' with type '{data_type}' must use field '{value_key_data_type}'."
            )
        elif not attr[value_key]:
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' must contain non-empty message attribute value for message attribute type '{data_type}'."
            )


def extract_tags(
    topic_arn: str, tags: TagList | None, is_create_topic_request: bool, store: SnsStore
) -> bool:
    existing_tags = list(store.sns_tags.get(topic_arn, []))
    if topic_arn in store.topic_subscriptions:
        if tags is None:
            tags = []
        for tag in tags:
            if is_create_topic_request and existing_tags is not None and tag not in existing_tags:
                return False
    return True
