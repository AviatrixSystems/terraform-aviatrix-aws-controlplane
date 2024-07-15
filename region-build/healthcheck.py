import boto3
import os
import socket
import time
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

    TASK_DEF_FAMILY = "AVX_PLATFORM_HA"

    ip = get_priv_ip("us-east-1", TASK_DEF_FAMILY)
    print("IP is", ip)


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


def check_port(ip, port, retries=3, interval=60, timeout=5):
    try:
        for i in range(retries):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))

            if result == 0:
                print(f"Successfully connected to {ip} on port {port}.")
                return True

            else:
                print(
                    f"Failed to connect to {ip} on port {port}. Sleeping for {interval} seconds."
                )
                time.sleep(interval)

        print(f"Failed to connect to {ip} on port {port} after {retries} retries.")
        return False

    except:
        print(f"Failed to connect to {ip} on port {port}.")
        return False

    finally:
        s.close()


def get_priv_ip(region, task_def_family):
    ecs_client = boto3.client("ecs", region)
    response = ecs_client.describe_task_definition(taskDefinition=task_def_family)
    env = response["taskDefinition"]["containerDefinitions"][0]["environment"]
    env_dict = {pair["name"]: pair["value"] for pair in env}
    priv_ip = env_dict.get("PRIV_IP")
    return priv_ip
