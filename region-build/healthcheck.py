import boto3
import os
import traceback
from datetime import datetime
from pprint import pprint


class AvxError(Exception):
    """Error class for Aviatrix exceptions"""


def lambda_handler(event, context):
    """Entry point of the lambda script"""

    print("START Time:", datetime.now())

    try:
        _lambda_handler(event, context)
    except AvxError as err:
        print("Operation failed due to: " + str(err))
    except Exception as err:
        print(str(traceback.format_exc()))
        print("Lambda function failed due to " + str(err))


def _lambda_handler(event, context):
    """Entry point of the lambda script without exception handling"""

    # print(f"Event: {event}")
    # print(f"Context: {context}")
    # pprint(dict(os.environ))

    region = os.environ.get("region")
    sns_topic_arn = os.environ.get("sns_topic_arn")
    test_message = "test"

    # print("Publishing Message to SNS")
    # publish_message_to_sns(sns_topic_arn, test_message, region)

    ecs_cluster = os.environ.get("ecs_cluster")
    ecs_task_def = os.environ.get("ecs_task_def")
    subnets = [os.environ.get("ecs_subnet_1"), os.environ.get("ecs_subnet_2")]
    security_groups = [os.environ.get("ecs_security_group")]

    # print("Triggering ECS")
    # run_ecs_task(ecs_cluster, ecs_task_def, subnets, security_groups, "ENABLED", region)


def publish_message_to_sns(topic_arn, message, region):
    sns_client = boto3.client("sns", region_name=region)
    response = sns_client.publish(TopicArn=topic_arn, Message=message)
    return response


def run_ecs_task(cluster, task_def, subnets, security_groups, assign_public_ip, region):
    ecs_client = boto3.client("ecs", region_name=region)
    response = ecs_client.run_task(
        cluster=cluster,
        taskDefinition=task_def,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets,
                "securityGroups": security_groups,
                "assignPublicIp": assign_public_ip,
            }
        },
    )
    return response
