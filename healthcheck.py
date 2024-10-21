import boto3
import json
import os
import socket
import sys
import time
import traceback
import urllib3


from datetime import datetime
from pip._vendor import requests
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

    region = os.environ.get("region")
    peer_region = os.environ.get("peer_region")
    sns_topic_arn = os.environ.get("sns_topic_arn")

    ecs_cluster = os.environ.get("ecs_cluster")
    ecs_task_def = os.environ.get("ecs_task_def")
    subnets = [os.environ.get("ecs_subnet_1"), os.environ.get("ecs_subnet_2")]
    security_groups = [os.environ.get("ecs_security_group")]

    TASK_DEF_FAMILY = "AVX_PLATFORM_HA"

    # Get the peer EIP if not set
    eip = os.environ.get("peer_eip")
    if eip == "":
        print("peer_eip not set, retrieving from peer region")
        eip = get_task_def_env_value(peer_region, TASK_DEF_FAMILY, "EIP")
        print("Setting peer_eip to", eip)
        response = update_lamba_env_vars(
            "aviatrix_healthcheck", region, "peer_eip", eip
        )
        print(response)

    # Get the peer private IP if not set
    ip = os.environ.get("peer_priv_ip")
    if ip == "":
        print("peer_priv_ip not set, retrieving from peer region")
        ip = get_task_def_env_value(peer_region, TASK_DEF_FAMILY, "PRIV_IP")
        print("Setting peer_priv_ip to", ip)
        response = update_lamba_env_vars(
            "aviatrix_healthcheck", region, "peer_priv_ip", ip
        )
        print(response)

    print(f"The private IP of the Controller in {peer_region} is {ip}.")
    print(f"Checking port 443 on {ip}.")

    message = json.dumps(
        {
            "FailingEIP": eip,
            "FailingPrivIP": ip,
            "FailingRegion": os.environ.get("peer_region"),
            "HealthCheckRule": os.environ.get("health_check_rule"),
            "LocalRegion": os.environ.get("region"),
            "Service": "Health Check",
        }
    )

    if check_port(ip, 443):
        print(f"Checking port: {ip}:443 is accessible")
    else:
        print(f"Checking port: {ip}:443 is not accessible")

        print("Publishing message to SNS")
        response = publish_message_to_sns(sns_topic_arn, message, region)
        print(response)

        print("Triggering ECS")
        response = run_ecs_task(
            ecs_cluster, ecs_task_def, subnets, security_groups, "ENABLED", region
        )
        print(response)


def publish_message_to_sns(topic_arn, message, region):
    sns_client = boto3.client("sns", region_name=region)
    response = sns_client.publish(TopicArn=topic_arn, Message=message)
    return response


def run_ecs_task(cluster, task_def, subnets, security_groups, assign_public_ip, region):
    ecs_client = boto3.client("ecs", region_name=region)
    response = ecs_client.run_task(
        cluster=cluster,
        count=1,
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
    try:
        ecs_client = boto3.client("ecs", region)
        response = ecs_client.describe_task_definition(taskDefinition=task_def_family)
    except Exception as e:
        print(e)
        print(
            "Verify that connectivity to AWS service endpoints from the private subnets associated with the Lambda function is allowed."
        )
        sys.exit(1)

    env = response["taskDefinition"]["containerDefinitions"][0]["environment"]
    env_dict = {pair["name"]: pair["value"] for pair in env}
    priv_ip = env_dict.get("PRIV_IP")
    return priv_ip


def get_task_def_env_value(region, task_def_family, key):
    try:
        ecs_client = boto3.client("ecs", region)
        response = ecs_client.describe_task_definition(taskDefinition=task_def_family)
    except Exception as e:
        print(e)
        print(
            "Verify that connectivity to AWS service endpoints from the private subnets associated with the Lambda function is allowed."
        )
        sys.exit(1)

    env = response["taskDefinition"]["containerDefinitions"][0]["environment"]
    env_dict = {pair["name"]: pair["value"] for pair in env}
    return env_dict.get(key)


def update_lamba_env_vars(function_name, region, key, value):
    client = boto3.client("lambda", region)
    response = client.get_function_configuration(FunctionName=function_name)
    current_env = response["Environment"]
    current_env["Variables"][key] = value
    try:
        response = client.update_function_configuration(
            FunctionName=function_name, Environment=current_env
        )
    except client.exceptions.ResourceConflictException as e:
        # Retry if there's already an update in progress
        time.sleep(60)
        response = client.update_function_configuration(
            FunctionName=function_name, Environment=current_env
        )
    return response
