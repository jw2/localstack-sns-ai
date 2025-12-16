import contextlib
import copy
import json
import logging
import re
from enum import StrEnum

from botocore.utils import InvalidArnException

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.sns import (
    BatchEntryIdsNotDistinctException,
    CheckIfPhoneNumberIsOptedOutResponse,
    ConfirmSubscriptionResponse,
    CreateEndpointResponse,
    CreatePlatformApplicationResponse,
    CreateTopicResponse,
    EndpointDisabledException,
    GetEndpointAttributesResponse,
    GetPlatformApplicationAttributesResponse,
    GetSMSAttributesResponse,
    GetSubscriptionAttributesResponse,
    GetTopicAttributesResponse,
    InvalidParameterException,
    ListEndpointsByPlatformApplicationResponse,
    ListPhoneNumbersOptedOutResponse,
    ListPlatformApplicationsResponse,
    ListSubscriptionsByTopicResponse,
    ListSubscriptionsResponse,
    ListTagsForResourceResponse,
    ListTopicsResponse,
    MapStringToString,
    MessageAttributeMap,
    NotFoundException,
    OptInPhoneNumberResponse,
    PhoneNumber,
    PublishBatchRequestEntryList,
    PublishBatchResponse,
    PublishBatchResultEntry,
    PublishResponse,
    SnsApi,
    String,
    SubscribeResponse,
    Subscription,
    SubscriptionAttributesMap,
    TagList,
    TagResourceResponse,
    TooManyEntriesInBatchRequestException,
    TopicAttributesMap,
    UntagResourceResponse,
    attributeName,
    attributeValue,
    authenticateOnUnsubscribe,
    boolean,
    messageStructure,
    nextToken,
    subscriptionARN,
    topicARN,
    topicName,
)
from localstack.constants import DEFAULT_AWS_ACCOUNT_ID
from localstack.http import Request, Response, route
from localstack.services.edge import ROUTER
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.sns import constants as sns_constants
from localstack.services.sns.certificate import SNS_SERVER_CERT
from localstack.services.sns.filter import FilterPolicyValidator
from localstack.services.sns.models import (
    PlatformApplicationDetails,
    PlatformEndpoint,
    SnsMessage,
    SnsMessageType,
    SnsStore,
    SnsSubscription,
    create_default_sns_topic_policy,
    sns_stores,
)
from localstack.services.sns.publisher import (
    PublishDispatcher,
    SnsBatchPublishContext,
    SnsPublishContext,
)
from localstack.services.sns.v3.internal_resources import register_sns_api_resource
from localstack.services.sns.v3.utils import (
    create_platform_endpoint_arn,
    create_subscription_arn,
    encode_subscription_token_with_region,
    extract_tags,
    get_next_page_token_from_arn,
    get_region_from_subscription_token,
    get_total_publish_size,
    parse_and_validate_platform_application_arn,
    parse_and_validate_topic_arn,
    validate_message_attributes,
    validate_subscription_attribute,
)
from localstack.state import StateVisitor
from localstack.utils.aws.arns import get_partition, parse_arn, sns_platform_application_arn
from localstack.utils.collections import PaginatedList, select_from_typed_dict

LOG = logging.getLogger(__name__)

SNS_TOPIC_NAME_PATTERN_FIFO = r"^[a-zA-Z0-9_-]{1,256}\.fifo$"
SNS_TOPIC_NAME_PATTERN = r"^[a-zA-Z0-9_-]{1,256}$"


class EndpointAttributeNames(StrEnum):
    CUSTOM_USER_DATA = "CustomUserData"
    Token = "Token"
    ENABLED = "Enabled"


SMS_ATTRIBUTE_NAMES = [
    "DeliveryStatusIAMRole",
    "DeliveryStatusSuccessSamplingRate",
    "DefaultSenderID",
    "DefaultSMSType",
    "UsageReportS3Bucket",
]
SMS_TYPES = ["Promotional", "Transactional"]
SMS_DEFAULT_SENDER_REGEX = r"^(?=[A-Za-z0-9]{1,11}$)(?=.*[A-Za-z])[A-Za-z0-9]+$"


class SnsProvider(SnsApi, ServiceLifecycleHook):
    """
    Internal SNS provider (v3) without Moto fallback.
    First milestone implements topics, subscriptions, and publish flows.
    """

    @route(sns_constants.SNS_CERT_ENDPOINT, methods=["GET"])
    def get_signature_cert_pem_file(self, request: Request):
        return Response(self._signature_cert_pem, 200)

    def __init__(self) -> None:
        super().__init__()
        self._publisher = PublishDispatcher()
        self._signature_cert_pem: str = SNS_SERVER_CERT

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(sns_stores)

    def on_before_stop(self):
        self._publisher.shutdown()

    def on_after_init(self):
        register_sns_api_resource(ROUTER)
        ROUTER.add(self.get_signature_cert_pem_file)

    @staticmethod
    def get_store(account_id: str, region_name: str) -> SnsStore:
        return sns_stores[account_id][region_name]

    def _get_topic(self, arn: str, context: RequestContext) -> dict:
        arn_data = parse_and_validate_topic_arn(arn)
        if context.region != arn_data["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")

        store = self.get_store(account_id=arn_data["account"], region_name=context.region)
        topic = store.topics.get(arn)
        if not topic:
            raise NotFoundException("Topic does not exist")
        return topic

    @staticmethod
    def _get_platform_application(platform_application_arn: str, context: RequestContext) -> dict:
        parse_and_validate_platform_application_arn(platform_application_arn)
        try:
            store = SnsProvider.get_store(context.account_id, context.region)
            return store.platform_applications[platform_application_arn].platform_application
        except KeyError:
            raise NotFoundException("PlatformApplication does not exist")

    ## Topic operations

    def create_topic(
        self,
        context: RequestContext,
        name: topicName,
        attributes: TopicAttributesMap | None = None,
        tags: TagList | None = None,
        data_protection_policy: attributeValue | None = None,
        **kwargs,
    ) -> CreateTopicResponse:
        attributes = attributes or {}
        store = self.get_store(context.account_id, context.region)

        if not re.match(
            SNS_TOPIC_NAME_PATTERN_FIFO if name.endswith(".fifo") else SNS_TOPIC_NAME_PATTERN, name
        ):
            raise InvalidParameterException("Invalid parameter: Topic Name")

        is_fifo = attributes.get("FifoTopic", "false").lower() == "true" or name.endswith(".fifo")
        if is_fifo and not name.endswith(".fifo"):
            raise InvalidParameterException(
                "Invalid parameter: Fifo Topic names must end with .fifo and must be made up of only uppercase and lowercase ASCII letters, numbers, underscores, and hyphens, and must be between 1 and 256 characters long."
            )
        if not is_fifo and name.endswith(".fifo"):
            # name indicates FIFO but attribute not set
            attributes["FifoTopic"] = "true"
            is_fifo = True

        topic_arn = (
            f"arn:{get_partition(context.region)}:sns:{context.region}:{context.account_id}:{name}"
        )
        existing_topic = store.topics.get(topic_arn)
        if existing_topic:
            existing_attrs = existing_topic["attributes"]
            # ensure provided attributes match existing
            for key, value in attributes.items():
                if existing_attrs.get(key) != value:
                    raise InvalidParameterException(
                        "Invalid parameter: Topic already exists with different attributes"
                    )
            if not extract_tags(topic_arn, tags, True, store):
                raise InvalidParameterException(
                    "Invalid parameter: Tags Reason: Topic already exists with different tags"
                )
            return CreateTopicResponse(TopicArn=topic_arn)

        topic_attributes = self._build_topic_attributes(
            context=context,
            topic_arn=topic_arn,
            name=name,
            input_attributes=attributes,
            fifo=is_fifo,
        )
        topic = {"arn": topic_arn, "name": name, "attributes": topic_attributes}
        store.topics[topic_arn] = topic
        store.topic_subscriptions.setdefault(topic_arn, [])

        if tags:
            self.tag_resource(context=context, resource_arn=topic_arn, tags=tags)

        return CreateTopicResponse(TopicArn=topic_arn)

    def _build_topic_attributes(
        self,
        context: RequestContext,
        topic_arn: str,
        name: str,
        input_attributes: TopicAttributesMap,
        fifo: bool,
    ) -> TopicAttributesMap:
        attributes: TopicAttributesMap = {
            "TopicArn": topic_arn,
            "Owner": context.account_id or DEFAULT_AWS_ACCOUNT_ID,
            "Policy": json.dumps(create_default_sns_topic_policy(topic_arn)),
            "DisplayName": input_attributes.get("DisplayName", ""),
            "DeliveryPolicy": input_attributes.get("DeliveryPolicy", ""),
            "EffectiveDeliveryPolicy": input_attributes.get("EffectiveDeliveryPolicy", ""),
            "SubscriptionsConfirmed": "0",
            "SubscriptionsDeleted": "0",
            "SubscriptionsPending": "0",
        }

        if fifo:
            attributes["FifoTopic"] = "true"
            attributes["ContentBasedDeduplication"] = input_attributes.get(
                "ContentBasedDeduplication", "false"
            )
        elif "FifoTopic" in input_attributes:
            # explicit false still stored for compatibility
            attributes["FifoTopic"] = input_attributes["FifoTopic"]

        # carry over any other attributes provided
        for key, value in input_attributes.items():
            if key in attributes:
                continue
            attributes[key] = value

        return attributes

    def get_topic_attributes(
        self, context: RequestContext, topic_arn: topicARN, **kwargs
    ) -> GetTopicAttributesResponse:
        topic = self._get_topic(topic_arn, context)
        attributes = copy.deepcopy(topic["attributes"])
        # keep deleted counter if present, default 0
        attributes.setdefault("SubscriptionsDeleted", "0")
        return GetTopicAttributesResponse(Attributes=attributes)

    def set_topic_attributes(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        attribute_name: attributeName,
        attribute_value: attributeValue | None = None,
        **kwargs,
    ) -> None:
        topic = self._get_topic(topic_arn, context)
        if attribute_name == "FifoTopic":
            raise InvalidParameterException("Invalid parameter: AttributeName")
        topic["attributes"][attribute_name] = attribute_value

    def delete_topic(self, context: RequestContext, topic_arn: topicARN, **kwargs) -> None:
        parsed = parse_and_validate_topic_arn(topic_arn)
        if parsed["region"] != context.region:
            raise InvalidParameterException("Invalid parameter: TopicArn")

        store = self.get_store(account_id=parsed["account"], region_name=context.region)
        store.topics.pop(topic_arn, None)
        topic_subscriptions = store.topic_subscriptions.pop(topic_arn, [])
        for topic_sub in topic_subscriptions:
            store.subscriptions.pop(topic_sub, None)
        store.subscription_filter_policy = {
            k: v
            for k, v in store.subscription_filter_policy.items()
            if k not in topic_subscriptions
        }
        store.sns_tags.pop(topic_arn, None)

    def add_permission(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        label: String,
        aws_account_id: list[String],
        action_name: list[String],
        **kwargs,
    ) -> None:
        # Basic validation to ensure topic exists. Permission data is not yet enforced.
        self._get_topic(topic_arn, context)
        return None

    def remove_permission(
        self, context: RequestContext, topic_arn: topicARN, label: String, **kwargs
    ) -> None:
        self._get_topic(topic_arn, context)
        return None

    def list_topics(
        self, context: RequestContext, next_token: nextToken | None = None, **kwargs
    ) -> ListTopicsResponse:
        store = self.get_store(context.account_id, context.region)
        topics = [{"TopicArn": t["arn"]} for t in list(store.topics.values())]
        topics = PaginatedList(topics)
        page, nxt = topics.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x["TopicArn"]),
            next_token=next_token,
            page_size=100,
        )
        response: ListTopicsResponse = {"Topics": page}
        if nxt:
            response["NextToken"] = nxt
        return response

    ## Subscribe operations

    def subscribe(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        protocol: String,
        endpoint: String = None,
        attributes: SubscriptionAttributesMap = None,
        return_subscription_arn: boolean = None,
        **kwargs,
    ) -> SubscribeResponse:
        parsed_topic_arn = parse_and_validate_topic_arn(topic_arn)
        if context.region != parsed_topic_arn["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")

        store = self.get_store(account_id=parsed_topic_arn["account"], region_name=context.region)
        topic = self._get_topic(topic_arn, context)

        if not endpoint:
            raise NotFoundException("Endpoint not specified in subscription")
        if protocol not in sns_constants.SNS_PROTOCOLS:
            raise InvalidParameterException(
                f"Invalid parameter: Amazon SNS does not support this protocol string: {protocol}"
            )
        elif protocol in ["http", "https"] and not endpoint.startswith(f"{protocol}://"):
            raise InvalidParameterException(
                "Invalid parameter: Endpoint must match the specified protocol"
            )
        elif protocol == "sms" and not sns_constants.E164_REGEX.match(endpoint):
            raise InvalidParameterException(f"Invalid SMS endpoint: {endpoint}")
        elif protocol == "sqs":
            try:
                parse_arn(endpoint)
            except InvalidArnException:
                raise InvalidParameterException("Invalid parameter: SQS endpoint ARN")

        elif protocol == "application":
            try:
                parse_arn(endpoint)
            except InvalidArnException:
                raise InvalidParameterException("Invalid parameter: ApplicationEndpoint ARN")

        if ".fifo" in endpoint and ".fifo" not in topic_arn:
            raise InvalidParameterException(
                "Invalid parameter: Invalid parameter: Endpoint Reason: FIFO SQS Queues can not be subscribed to standard SNS topics"
            )

        sub_attributes = copy.deepcopy(attributes) if attributes else None
        if sub_attributes:
            for attr_name, attr_value in sub_attributes.items():
                validate_subscription_attribute(
                    attribute_name=attr_name,
                    attribute_value=attr_value,
                    topic_arn=topic_arn,
                    endpoint=endpoint,
                    is_subscribe_call=True,
                )
                if raw_msg_delivery := sub_attributes.get("RawMessageDelivery"):
                    sub_attributes["RawMessageDelivery"] = raw_msg_delivery.lower()

        for existing_topic_subscription in store.topic_subscriptions.get(topic_arn, []):
            sub = store.subscriptions.get(existing_topic_subscription, {})
            if sub.get("Endpoint") == endpoint:
                if sub_attributes:
                    for attr in sns_constants.VALID_SUBSCRIPTION_ATTR_NAME:
                        if (new_attr := sub_attributes.get(attr)) and sub.get(attr) != new_attr:
                            raise InvalidParameterException(
                                "Invalid parameter: Attributes Reason: Subscription already exists with different attributes"
                            )

                return SubscribeResponse(SubscriptionArn=sub["SubscriptionArn"])

        principal = sns_constants.DUMMY_SUBSCRIPTION_PRINCIPAL.format(
            partition=get_partition(context.region), account_id=context.account_id
        )
        subscription_arn = create_subscription_arn(topic_arn)
        subscription = SnsSubscription(
            TopicArn=topic_arn,
            Endpoint=endpoint,
            Protocol=protocol,
            SubscriptionArn=subscription_arn,
            PendingConfirmation="true",
            Owner=context.account_id,
            RawMessageDelivery="false",
            FilterPolicyScope="MessageAttributes",
            SubscriptionPrincipal=principal,
        )
        if sub_attributes:
            subscription.update(sub_attributes)
            if "FilterPolicy" in sub_attributes:
                filter_policy = (
                    json.loads(sub_attributes["FilterPolicy"])
                    if sub_attributes["FilterPolicy"]
                    else None
                )
                if filter_policy:
                    validator = FilterPolicyValidator(
                        scope=subscription.get("FilterPolicyScope", "MessageAttributes"),
                        is_subscribe_call=True,
                    )
                    validator.validate_filter_policy(filter_policy)

                store.subscription_filter_policy[subscription_arn] = filter_policy

        store.subscriptions[subscription_arn] = subscription
        topic_subscriptions = store.topic_subscriptions.setdefault(topic_arn, [])
        topic_subscriptions.append(subscription_arn)

        subscription_token = encode_subscription_token_with_region(region=context.region)
        store.subscription_tokens[subscription_token] = subscription_arn

        response_subscription_arn = subscription_arn
        if protocol in ["http", "https"]:
            message_ctx = SnsMessage(
                type=SnsMessageType.SubscriptionConfirmation,
                token=subscription_token,
                message=f"You have chosen to subscribe to the topic {topic_arn}.\nTo confirm the subscription, visit the SubscribeURL included in this message.",
            )
            publish_ctx = SnsPublishContext(
                message=message_ctx,
                store=store,
                request_headers=context.request.headers,
                topic_attributes=topic["attributes"],
            )
            self._publisher.publish_to_topic_subscriber(
                ctx=publish_ctx,
                topic_arn=topic_arn,
                subscription_arn=subscription_arn,
            )
            if not return_subscription_arn:
                response_subscription_arn = "pending confirmation"

        elif protocol not in ["email", "email-json"]:
            subscription["PendingConfirmation"] = "false"
            subscription["ConfirmationWasAuthenticated"] = "true"

        return SubscribeResponse(SubscriptionArn=response_subscription_arn)

    def confirm_subscription(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        token: String,
        authenticate_on_unsubscribe: authenticateOnUnsubscribe = None,
        **kwargs,
    ) -> ConfirmSubscriptionResponse:
        try:
            parsed_arn = parse_arn(topic_arn)
        except InvalidArnException:
            raise InvalidParameterException("Invalid parameter: Topic")

        store = self.get_store(account_id=parsed_arn["account"], region_name=parsed_arn["region"])

        if parsed_arn["region"] != get_region_from_subscription_token(token):
            raise InvalidParameterException("Invalid parameter: Topic")

        subscription_arn = store.subscription_tokens.get(token)
        if not subscription_arn:
            raise InvalidParameterException("Invalid parameter: Token")

        subscription = store.subscriptions.get(subscription_arn)
        if not subscription:
            raise InvalidParameterException("Invalid parameter: Token")

        if subscription.get("PendingConfirmation") == "false":
            return ConfirmSubscriptionResponse(SubscriptionArn=subscription_arn)

        subscription["PendingConfirmation"] = "false"
        subscription["ConfirmationWasAuthenticated"] = "true"

        return ConfirmSubscriptionResponse(SubscriptionArn=subscription_arn)

    def set_subscription_attributes(
        self,
        context: RequestContext,
        subscription_arn: subscriptionARN,
        attribute_name: attributeName,
        attribute_value: attributeValue = None,
        **kwargs,
    ) -> None:
        store = self.get_store(account_id=context.account_id, region_name=context.region)
        sub = store.subscriptions.get(subscription_arn)
        if not sub:
            raise NotFoundException("Subscription does not exist")

        validate_subscription_attribute(
            attribute_name=attribute_name,
            attribute_value=attribute_value,
            topic_arn=sub["TopicArn"],
            endpoint=sub["Endpoint"],
        )
        if attribute_name == "RawMessageDelivery":
            attribute_value = attribute_value.lower()

        elif attribute_name == "FilterPolicy":
            filter_policy = json.loads(attribute_value) if attribute_value else None
            if filter_policy:
                validator = FilterPolicyValidator(
                    scope=sub.get("FilterPolicyScope", "MessageAttributes"),
                    is_subscribe_call=False,
                )
                validator.validate_filter_policy(filter_policy)

            store.subscription_filter_policy[subscription_arn] = filter_policy

        sub[attribute_name] = attribute_value

    def get_subscription_attributes(
        self, context: RequestContext, subscription_arn: subscriptionARN, **kwargs
    ) -> GetSubscriptionAttributesResponse:
        store = self.get_store(account_id=context.account_id, region_name=context.region)
        sub = store.subscriptions.get(subscription_arn)
        if not sub:
            raise NotFoundException("Subscription does not exist")
        removed_attrs = ["sqs_queue_url"]
        if "FilterPolicyScope" in sub and not sub.get("FilterPolicy"):
            removed_attrs.append("FilterPolicyScope")
            removed_attrs.append("FilterPolicy")
        elif "FilterPolicy" in sub and "FilterPolicyScope" not in sub:
            sub["FilterPolicyScope"] = "MessageAttributes"

        attributes = {k: v for k, v in sub.items() if k not in removed_attrs}
        return GetSubscriptionAttributesResponse(Attributes=attributes)

    def list_subscriptions(
        self, context: RequestContext, next_token: nextToken = None, **kwargs
    ) -> ListSubscriptionsResponse:
        store = self.get_store(context.account_id, context.region)
        subscriptions = [
            select_from_typed_dict(Subscription, sub) for sub in list(store.subscriptions.values())
        ]
        paginated_subscriptions = PaginatedList(subscriptions)
        page, nxt = paginated_subscriptions.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x["SubscriptionArn"]),
            page_size=100,
            next_token=next_token,
        )

        response = ListSubscriptionsResponse(Subscriptions=page)
        if nxt:
            response["NextToken"] = nxt
        return response

    def list_subscriptions_by_topic(
        self, context: RequestContext, topic_arn: topicARN, next_token: nextToken = None, **kwargs
    ) -> ListSubscriptionsByTopicResponse:
        self._get_topic(topic_arn, context)
        parsed_topic_arn = parse_and_validate_topic_arn(topic_arn)
        store = self.get_store(parsed_topic_arn["account"], parsed_topic_arn["region"])
        sns_subscriptions = store.get_topic_subscriptions(topic_arn)
        subscriptions = [select_from_typed_dict(Subscription, sub) for sub in sns_subscriptions]

        paginated_subscriptions = PaginatedList(subscriptions)
        page, nxt = paginated_subscriptions.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x["SubscriptionArn"]),
            page_size=100,
            next_token=next_token,
        )

        response = ListSubscriptionsResponse(Subscriptions=page)
        if nxt:
            response["NextToken"] = nxt
        return response

    def unsubscribe(
        self, context: RequestContext, subscription_arn: subscriptionARN, **kwargs
    ) -> None:
        if subscription_arn is None:
            raise InvalidParameterException(
                "Invalid parameter: SubscriptionArn Reason: no value for required parameter",
            )
        count = len(subscription_arn.split(":"))
        try:
            parsed_arn = parse_arn(subscription_arn)
        except InvalidArnException:
            raise InvalidParameterException(
                f"Invalid parameter: SubscriptionArn Reason: An ARN must have at least 6 elements, not {count}"
            )

        account_id = parsed_arn["account"]
        region_name = parsed_arn["region"]

        store = self.get_store(account_id=account_id, region_name=region_name)
        if count == 6 and subscription_arn not in store.subscriptions:
            raise InvalidParameterException("Invalid parameter: SubscriptionId")

        subscription = store.subscriptions.get(subscription_arn)
        if not subscription:
            return

        topic = self._get_topic(subscription["TopicArn"], context)

        if subscription["Protocol"] in ["http", "https"]:
            subscription_token = encode_subscription_token_with_region(region=context.region)
            message_ctx = SnsMessage(
                type=SnsMessageType.UnsubscribeConfirmation,
                token=subscription_token,
                message=f"You have chosen to deactivate subscription {subscription_arn}.\nTo cancel this operation and restore the subscription, visit the SubscribeURL included in this message.",
            )
            publish_ctx = SnsPublishContext(
                message=message_ctx,
                store=store,
                request_headers=context.request.headers,
                topic_attributes=topic["attributes"],
            )
            self._publisher.publish_to_topic_subscriber(
                publish_ctx,
                topic_arn=subscription["TopicArn"],
                subscription_arn=subscription_arn,
            )

        with contextlib.suppress(ValueError):
            store.topic_subscriptions[subscription["TopicArn"]].remove(subscription_arn)
        store.subscription_filter_policy.pop(subscription_arn, None)
        store.subscriptions.pop(subscription_arn, None)

    ## Publish operations

    def publish(
        self,
        context: RequestContext,
        message: String,
        topic_arn: topicARN = None,
        target_arn: String = None,
        phone_number: String = None,
        subject: String = None,
        message_structure: messageStructure = None,
        message_attributes: MessageAttributeMap = None,
        message_deduplication_id: String = None,
        message_group_id: String = None,
        **kwargs,
    ) -> PublishResponse:
        if subject == "":
            raise InvalidParameterException("Invalid parameter: Subject")
        if not message or all(not m for m in message):
            raise InvalidParameterException("Invalid parameter: Empty message")

        if phone_number and not sns_constants.E164_REGEX.match(phone_number):
            raise InvalidParameterException(
                f"Invalid parameter: PhoneNumber Reason: {phone_number} is not valid to publish to"
            )

        if message_attributes:
            validate_message_attributes(message_attributes)

        if (
            get_total_publish_size(message, message_attributes)
            > sns_constants.MAXIMUM_MESSAGE_LENGTH
        ):
            raise InvalidParameterException("Invalid parameter: Message too long")

        topic_or_target_arn = topic_arn or target_arn
        topic_model = None

        if is_fifo := (topic_or_target_arn and ".fifo" in topic_or_target_arn):
            if not message_group_id:
                raise InvalidParameterException(
                    "Invalid parameter: The MessageGroupId parameter is required for FIFO topics",
                )
            topic_model = self._get_topic(topic_or_target_arn, context)
            if topic_model["attributes"].get("ContentBasedDeduplication", "false") == "false":
                if not message_deduplication_id:
                    raise InvalidParameterException(
                        "Invalid parameter: The topic should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly",
                    )
        elif message_deduplication_id:
            raise InvalidParameterException(
                "Invalid parameter: MessageDeduplicationId Reason: The request includes MessageDeduplicationId parameter that is not valid for this topic type"
            )

        is_endpoint_publish = target_arn and ":endpoint/" in target_arn
        if message_structure == "json":
            try:
                message = json.loads(message)
                message = {key: field for key, field in message.items() if isinstance(field, str)}
                if "default" not in message and not is_endpoint_publish:
                    raise InvalidParameterException(
                        "Invalid parameter: Message Structure - No default entry in JSON message body"
                    )
            except json.JSONDecodeError:
                raise InvalidParameterException(
                    "Invalid parameter: Message Structure - JSON message body failed to parse"
                )

        store: SnsStore
        if not phone_number:
            parsed_arn = parse_and_validate_topic_arn(topic_or_target_arn)
            store = self.get_store(account_id=parsed_arn["account"], region_name=context.region)
            if is_endpoint_publish:
                if not (platform_endpoint := store.platform_endpoints.get(target_arn)):
                    raise InvalidParameterException(
                        "Invalid parameter: TargetArn Reason: No endpoint found for the target arn specified"
                    )
                if (
                    platform_endpoint.platform_endpoint["Attributes"]
                    .get("Enabled", "false")
                    .lower()
                    != "true"
                ):
                    raise EndpointDisabledException("Endpoint is disabled")
            if not is_endpoint_publish:
                topic_model = topic_model or self._get_topic(topic_or_target_arn, context)
        else:
            store = self.get_store(account_id=context.account_id, region_name=context.region)

        message_ctx = SnsMessage(
            type=SnsMessageType.Notification,
            message=message,
            message_attributes=message_attributes,
            message_deduplication_id=message_deduplication_id,
            message_group_id=message_group_id,
            message_structure=message_structure,
            subject=subject,
            is_fifo=is_fifo,
        )
        publish_ctx = SnsPublishContext(
            message=message_ctx, store=store, request_headers=context.request.headers
        )

        if is_endpoint_publish:
            self._publisher.publish_to_application_endpoint(
                ctx=publish_ctx, endpoint_arn=target_arn
            )
        elif phone_number:
            self._publisher.publish_to_phone_number(ctx=publish_ctx, phone_number=phone_number)
        else:
            publish_ctx.topic_attributes |= topic_model["attributes"]
            self._publisher.publish_to_topic(publish_ctx, topic_or_target_arn)

        if is_fifo:
            return PublishResponse(
                MessageId=message_ctx.message_id, SequenceNumber=message_ctx.sequencer_number
            )

        return PublishResponse(MessageId=message_ctx.message_id)

    def publish_batch(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        publish_batch_request_entries: PublishBatchRequestEntryList,
        **kwargs,
    ) -> PublishBatchResponse:
        if len(publish_batch_request_entries) > 10:
            raise TooManyEntriesInBatchRequestException(
                "The batch request contains more entries than permissible."
            )

        parsed_arn = parse_and_validate_topic_arn(topic_arn)
        store = self.get_store(account_id=parsed_arn["account"], region_name=context.region)
        topic = self._get_topic(topic_arn, context)

        ids = [entry["Id"] for entry in publish_batch_request_entries]
        if len(set(ids)) != len(publish_batch_request_entries):
            raise BatchEntryIdsNotDistinctException(
                "Two or more batch entries in the request have the same Id."
            )

        response: PublishBatchResponse = {"Successful": [], "Failed": []}

        total_batch_size = 0
        message_contexts = []
        for entry_index, entry in enumerate(publish_batch_request_entries, start=1):
            message_payload = entry.get("Message")
            message_attributes = entry.get("MessageAttributes", {})
            if message_attributes:
                validate_message_attributes(message_attributes, position=entry_index)

            total_batch_size += get_total_publish_size(message_payload, message_attributes)

            if entry.get("MessageStructure") == "json":
                try:
                    message = json.loads(message_payload)
                    message = {
                        key: field for key, field in message.items() if isinstance(field, str)
                    }
                    if "default" not in message:
                        raise InvalidParameterException(
                            "Invalid parameter: Message Structure - No default entry in JSON message body"
                        )
                    entry["Message"] = message  # noqa
                except json.JSONDecodeError:
                    raise InvalidParameterException(
                        "Invalid parameter: Message Structure - JSON message body failed to parse"
                    )

            if is_fifo := (".fifo" in topic_arn):
                if not all("MessageGroupId" in entry for entry in publish_batch_request_entries):
                    raise InvalidParameterException(
                        "Invalid parameter: The MessageGroupId parameter is required for FIFO topics"
                    )
                if topic["attributes"].get("ContentBasedDeduplication", "false") == "false":
                    if not all(
                        "MessageDeduplicationId" in entry for entry in publish_batch_request_entries
                    ):
                        raise InvalidParameterException(
                            "Invalid parameter: The topic should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly",
                        )

            msg_ctx = SnsMessage.from_batch_entry(entry, is_fifo=is_fifo)
            message_contexts.append(msg_ctx)
            success = PublishBatchResultEntry(
                Id=entry["Id"],
                MessageId=msg_ctx.message_id,
            )
            if is_fifo:
                success["SequenceNumber"] = msg_ctx.sequencer_number
            response["Successful"].append(success)

        if total_batch_size > sns_constants.MAXIMUM_MESSAGE_LENGTH:
            raise CommonServiceException(
                code="BatchRequestTooLong",
                message="The length of all the messages put together is more than the limit.",
                sender_fault=True,
            )

        publish_ctx = SnsBatchPublishContext(
            messages=message_contexts,
            store=store,
            request_headers=context.request.headers,
            topic_attributes=topic["attributes"],
        )
        self._publisher.publish_batch_to_topic(publish_ctx, topic_arn)

        return response

    #
    # PlatformApplications
    #
    def create_platform_application(
        self,
        context: RequestContext,
        name: String,
        platform: String,
        attributes: MapStringToString,
        **kwargs,
    ) -> CreatePlatformApplicationResponse:
        _validate_platform_application_name(name)
        if platform not in sns_constants.VALID_APPLICATION_PLATFORMS:
            raise InvalidParameterException(
                f"Invalid parameter: Platform Reason: {platform} is not supported"
            )

        attributes = attributes or {}
        allow_empty_attributes = platform in {"APNS", "GCM"} and not attributes
        if not allow_empty_attributes:
            _validate_platform_application_attributes(attributes)

            if "PlatformCredential" in attributes and "PlatformPrincipal" not in attributes:
                raise InvalidParameterException(
                    "Invalid parameter: Attributes Reason: PlatformCredential attribute provided without PlatformPrincipal"
                )

            if "PlatformPrincipal" in attributes and "PlatformCredential" not in attributes:
                raise InvalidParameterException(
                    "Invalid parameter: Attributes Reason: PlatformPrincipal attribute provided without PlatformCredential"
                )

        store = self.get_store(context.account_id, context.region)
        # We are not validating the access data here like AWS does (against ADM and the like)
        attributes = attributes.copy()
        attributes.pop("PlatformPrincipal", None)
        attributes.pop("PlatformCredential", None)
        _attributes = {"Enabled": "true"}
        _attributes.update(attributes)
        application_arn = sns_platform_application_arn(
            platform_application_name=name,
            platform=platform,
            account_id=context.account_id,
            region_name=context.region,
        )
        platform_application_details = PlatformApplicationDetails(
            platform_application={
                "PlatformApplicationArn": application_arn,
                "Attributes": _attributes,
            },
            platform_endpoints={},
        )
        store.platform_applications[application_arn] = platform_application_details

        return platform_application_details.platform_application

    def delete_platform_application(
        self, context: RequestContext, platform_application_arn: String, **kwargs
    ) -> None:
        store = self.get_store(context.account_id, context.region)
        store.platform_applications.pop(platform_application_arn, None)

    def list_platform_applications(
        self, context: RequestContext, next_token: String | None = None, **kwargs
    ) -> ListPlatformApplicationsResponse:
        store = self.get_store(context.account_id, context.region)
        platform_applications = store.platform_applications.values()
        paginated_applications = PaginatedList(platform_applications)
        page, token = paginated_applications.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(
                x.platform_application["PlatformApplicationArn"]
            ),
            page_size=100,
            next_token=next_token,
        )

        response = ListPlatformApplicationsResponse(
            PlatformApplications=[app.platform_application for app in page]
        )
        if token:
            response["NextToken"] = token
        return response

    def get_platform_application_attributes(
        self, context: RequestContext, platform_application_arn: String, **kwargs
    ) -> GetPlatformApplicationAttributesResponse:
        platform_application = self._get_platform_application(platform_application_arn, context)
        attributes = platform_application["Attributes"]
        return GetPlatformApplicationAttributesResponse(Attributes=attributes)

    def set_platform_application_attributes(
        self,
        context: RequestContext,
        platform_application_arn: String,
        attributes: MapStringToString,
        **kwargs,
    ) -> None:
        parse_and_validate_platform_application_arn(platform_application_arn)
        _validate_platform_application_attributes(attributes)

        platform_application = self._get_platform_application(platform_application_arn, context)
        platform_application["Attributes"].update(attributes)

    #
    # Platform Endpoints
    #
    def create_platform_endpoint(
        self,
        context: RequestContext,
        platform_application_arn: String,
        token: String,
        custom_user_data: String | None = None,
        attributes: MapStringToString | None = None,
        **kwargs,
    ) -> CreateEndpointResponse:
        store = self.get_store(context.account_id, context.region)
        application = store.platform_applications.get(platform_application_arn)
        if not application:
            raise NotFoundException("PlatformApplication does not exist")
        endpoint_arn = application.platform_endpoints.get(token, {})
        attributes = attributes or {}
        _validate_endpoint_attributes(attributes, allow_empty=True)
        attributes.setdefault(EndpointAttributeNames.CUSTOM_USER_DATA, custom_user_data)
        _attributes = {"Enabled": "true", "Token": token, **attributes}
        if endpoint_arn and (
            platform_endpoint_details := store.platform_endpoints.get(endpoint_arn)
        ):
            if platform_endpoint_details.platform_endpoint["Attributes"] != _attributes:
                raise InvalidParameterException(
                    f"Invalid parameter: Token Reason: Endpoint {endpoint_arn} already exists with the same Token, but different attributes."
                )
            return CreateEndpointResponse(EndpointArn=endpoint_arn)

        endpoint_arn = create_platform_endpoint_arn(platform_application_arn)
        platform_endpoint = PlatformEndpoint(
            platform_application_arn=platform_application_arn,
            platform_endpoint={"Attributes": _attributes, "EndpointArn": endpoint_arn},
        )
        store.platform_endpoints[endpoint_arn] = platform_endpoint
        application.platform_endpoints[token] = endpoint_arn

        return CreateEndpointResponse(EndpointArn=endpoint_arn)

    def delete_endpoint(self, context: RequestContext, endpoint_arn: String, **kwargs) -> None:
        store = self.get_store(context.account_id, context.region)
        platform_endpoint_details = store.platform_endpoints.pop(endpoint_arn, None)
        if platform_endpoint_details:
            platform_application = store.platform_applications.get(
                platform_endpoint_details.platform_application_arn
            )
            if platform_application:
                platform_endpoint = platform_endpoint_details.platform_endpoint
                platform_application.platform_endpoints.pop(
                    platform_endpoint["Attributes"]["Token"], None
                )

    def list_endpoints_by_platform_application(
        self,
        context: RequestContext,
        platform_application_arn: String,
        next_token: String | None = None,
        **kwargs,
    ) -> ListEndpointsByPlatformApplicationResponse:
        store = self.get_store(context.account_id, context.region)
        platform_application = store.platform_applications.get(platform_application_arn)
        if not platform_application:
            raise NotFoundException("PlatformApplication does not exist")
        endpoint_arns = platform_application.platform_endpoints.values()
        paginated_endpoint_arns = PaginatedList(endpoint_arns)
        page, token = paginated_endpoint_arns.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x),
            page_size=100,
            next_token=next_token,
        )

        response = ListEndpointsByPlatformApplicationResponse(
            Endpoints=[
                store.platform_endpoints[endpoint_arn].platform_endpoint
                for endpoint_arn in page
                if endpoint_arn in store.platform_endpoints
            ]
        )
        if token:
            response["NextToken"] = token
        return response

    def get_endpoint_attributes(
        self, context: RequestContext, endpoint_arn: String, **kwargs
    ) -> GetEndpointAttributesResponse:
        store = self.get_store(context.account_id, context.region)
        platform_endpoint_details = store.platform_endpoints.get(endpoint_arn)
        if not platform_endpoint_details:
            raise NotFoundException("Endpoint does not exist")
        attributes = platform_endpoint_details.platform_endpoint["Attributes"]
        return GetEndpointAttributesResponse(Attributes=attributes)

    def set_endpoint_attributes(
        self, context: RequestContext, endpoint_arn: String, attributes: MapStringToString, **kwargs
    ) -> None:
        store = self.get_store(context.account_id, context.region)
        platform_endpoint_details = store.platform_endpoints.get(endpoint_arn)
        if not platform_endpoint_details:
            raise NotFoundException("Endpoint does not exist")
        _validate_endpoint_attributes(attributes)
        attributes = attributes or {}
        platform_endpoint_details.platform_endpoint["Attributes"].update(attributes)

    #
    # Sms operations
    #
    def set_sms_attributes(
        self, context: RequestContext, attributes: MapStringToString, **kwargs
    ) -> None:
        _validate_sms_attributes(attributes)
        store = self.get_store(context.account_id, context.region)
        _set_sms_attribute_default(store)
        store.sms_attributes.update(attributes)

    def get_sms_attributes(
        self, context: RequestContext, attributes: list[str] | None = None, **kwargs
    ) -> GetSMSAttributesResponse:
        store = self.get_store(context.account_id, context.region)
        _set_sms_attribute_default(store)
        if attributes is None:
            attributes = []
        response: dict[str, str] = {}
        for attr in attributes:
            value = store.sms_attributes.get(attr)
            if value is not None:
                response[attr] = value
        if not attributes:
            response = store.sms_attributes.copy()
        return GetSMSAttributesResponse(attributes=response)

    #
    # Phone number operations
    #

    def check_if_phone_number_is_opted_out(
        self, context: RequestContext, phone_number: PhoneNumber, **kwargs
    ) -> CheckIfPhoneNumberIsOptedOutResponse:
        store = self.get_store(context.account_id, context.region)
        return CheckIfPhoneNumberIsOptedOutResponse(
            isOptedOut=phone_number in store.phone_numbers_opted_out
        )

    def list_phone_numbers_opted_out(
        self, context: RequestContext, next_token: String | None = None, **kwargs
    ) -> ListPhoneNumbersOptedOutResponse:
        store = self.get_store(context.account_id, context.region)
        numbers_opted_out = PaginatedList(store.phone_numbers_opted_out)
        page, nxt = numbers_opted_out.get_page(
            token_generator=lambda x: x,
            next_token=next_token,
            page_size=100,
        )
        phone_numbers = {"phoneNumbers": page}
        if nxt:
            phone_numbers["nextToken"] = nxt
        return ListPhoneNumbersOptedOutResponse(**phone_numbers)

    def opt_in_phone_number(
        self, context: RequestContext, phone_number: PhoneNumber, **kwargs
    ) -> OptInPhoneNumberResponse:
        store = self.get_store(context.account_id, context.region)
        with contextlib.suppress(ValueError):
            store.phone_numbers_opted_out.remove(phone_number)
        return OptInPhoneNumberResponse()

    ## Tagging (minimal support for topic tags used by tests)

    def tag_resource(
        self, context: RequestContext, resource_arn: str, tags: TagList, **kwargs
    ) -> TagResourceResponse:
        unique_tag_keys = {tag["Key"] for tag in tags}
        if len(unique_tag_keys) < len(tags):
            raise InvalidParameterException("Invalid parameter: Duplicated keys are not allowed.")

        store = self.get_store(context.account_id, context.region)
        existing_tags = store.sns_tags.get(resource_arn, [])

        def existing_tag_index(_item):
            for idx, tag in enumerate(existing_tags):
                if _item["Key"] == tag["Key"]:
                    return idx
            return None

        for item in tags:
            existing_index = existing_tag_index(item)
            if existing_index is None:
                existing_tags.append(item)
            else:
                existing_tags[existing_index] = item

        store.sns_tags[resource_arn] = existing_tags
        return TagResourceResponse()

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: str, **kwargs
    ) -> ListTagsForResourceResponse:
        store = self.get_store(context.account_id, context.region)
        tags = store.sns_tags.setdefault(resource_arn, [])
        return ListTagsForResourceResponse(Tags=tags)

    def untag_resource(
        self, context: RequestContext, resource_arn: str, tag_keys: list[str], **kwargs
    ) -> UntagResourceResponse:
        store = self.get_store(context.account_id, context.region)
        existing_tags = store.sns_tags.setdefault(resource_arn, [])
        store.sns_tags[resource_arn] = [t for t in existing_tags if t["Key"] not in tag_keys]
        return UntagResourceResponse()


def _validate_platform_application_name(name: str) -> None:
    reason = ""
    if not name:
        reason = "cannot be empty"
    elif not re.match(r"^.{0,256}$", name):
        reason = "must be at most 256 characters long"
    elif not re.match(r"^[A-Za-z0-9._-]+$", name):
        reason = "must contain only characters 'a'-'z', 'A'-'Z', '0'-'9', '_', '-', and '.'"

    if reason:
        raise InvalidParameterException(f"Invalid parameter: {name} Reason: {reason}")


def _check_empty_attributes(attributes: dict) -> None:
    if not attributes:
        raise CommonServiceException(
            code="ValidationError",
            message="1 validation error detected: Value null at 'attributes' failed to satisfy constraint: Member must not be null",
            sender_fault=True,
        )


def _validate_platform_application_attributes(attributes: dict) -> None:
    _check_empty_attributes(attributes)


def _validate_endpoint_attributes(attributes: dict, allow_empty: bool = False) -> None:
    if not allow_empty:
        _check_empty_attributes(attributes)
    for key in attributes:
        if key not in EndpointAttributeNames:
            raise InvalidParameterException(
                f"Invalid parameter: Attributes Reason: Invalid attribute name: {key}"
            )
    if len(attributes.get(EndpointAttributeNames.CUSTOM_USER_DATA, "")) > 2048:
        raise InvalidParameterException(
            "Invalid parameter: Attributes Reason: Invalid value for attribute: CustomUserData: must be at most 2048 bytes long in UTF-8 encoding"
        )


def _validate_sms_attributes(attributes: dict) -> None:
    for k, v in attributes.items():
        if k not in SMS_ATTRIBUTE_NAMES:
            raise InvalidParameterException(f"{k} is not a valid attribute")
    default_send_id = attributes.get("DefaultSendID")
    if default_send_id and not re.match(SMS_DEFAULT_SENDER_REGEX, default_send_id):
        raise InvalidParameterException("DefaultSendID is not a valid attribute")
    sms_type = attributes.get("DefaultSMSType")
    if sms_type and sms_type not in SMS_TYPES:
        raise InvalidParameterException("DefaultSMSType is invalid")


def _set_sms_attribute_default(store: SnsStore) -> None:
    store.sms_attributes.setdefault("MonthlySpendLimit", "1")
