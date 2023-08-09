""" Aviatrix Controller Deployment with HA script """
import time
import copy
import os
import uuid
import json
import pprint
import threading
import urllib.request
import urllib.error
import urllib.parse
from urllib.error import HTTPError
from urllib.request import build_opener, HTTPHandler, Request
import traceback
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import requests
import boto3
import botocore
import re
import copilot_main as cp_lib
import aws_utils as aws_utils



urllib3.disable_warnings(InsecureRequestWarning)

VERSION = "0.09"

HANDLE_HA_TIMEOUT = 1200
MAX_LOGIN_TIMEOUT = 800
WAIT_DELAY = 30

INITIAL_SETUP_WAIT = 180
INITIAL_SETUP_DELAY = 10

INITIAL_SETUP_API_WAIT = 20
MAXIMUM_BACKUP_AGE = 24 * 3600 * 3  # 3 days
AWS_US_EAST_REGION = "us-east-1"
VERSION_PREFIX = "UserConnect-"

QUEUE_TIMEOUT = 120
TASK_DEF_FAMILY = "AVX_PLATFORM_HA"

mask = lambda input: input[0:5] + "*" * 15 if isinstance(input, str) else ""


class AvxError(Exception):
    """Error class for Aviatrix exceptions"""


def main():
    """Entry point for the docker container."""
    print("Aviatrix Platform HA Version " + VERSION)
    try:
        print(f"START - {time.strftime('%H:%M:%S', time.localtime())}")
        ecs_handler()
        print(f"END - {time.strftime('%H:%M:%S', time.localtime())}")
    except AvxError as err:
        print("Operation failed due to: " + str(err))
    except Exception as err:  # pylint: disable=broad-except
        print(str(traceback.format_exc()))
        print("ECS Task failed due to " + str(err))


def ecs_handler():
    queue_region = os.environ.get("SQS_QUEUE_REGION")
    print("Queue region: %s" % queue_region)

    # Setup boto3 clients
    ec2_client = boto3.client("ec2")
    sqs_client = boto3.client("sqs", region_name=queue_region)
    sqs_resource = boto3.resource("sqs", region_name=queue_region)
    ecs_client = boto3.client("ecs")

    queue_name = os.environ.get("SQS_QUEUE_NAME")
    print(f"SQS Queue Name: {queue_name}")
    queue_url = sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
    print(f"SQS Queue URL: {queue_url}")
    queue = sqs_resource.Queue(queue_url)

    # Poll messages in the SQS queue.
    queue_messages = queue.receive_messages(
        MaxNumberOfMessages=1,
        WaitTimeSeconds=20,
        VisibilityTimeout=QUEUE_TIMEOUT,
    )
    if not queue_messages:
        print("No message in the queue. Exiting.")
        return

    print("Received message from SQS queue")
    print(queue_messages[0].body)
    event = json.loads(queue_messages[0].body)

    # Delete message from SQS
    #
    # We are deleting the message immediately because some tasks may take a long time to run. If we exceed the
    # SQS visibility timeout, the message will be put back into SQS which may lead to 2 problems:
    # 1. If another task gets invoked before the first task is done processing the message, but after the SQS
    #    visibility timeout, the message could be processed again
    # 2. We’ll get into the scenario where we have more messages than task invocations since the task that should
    #    have processed a new message is processing an old message instead
    response = queue.delete_messages(
        Entries=[
            {
                "Id": queue_messages[0].message_id,
                "ReceiptHandle": queue_messages[0].receipt_handle,
            }
        ]
    )
    print("Deleting message %s from SQS queue: %s" % (event["MessageId"], response))

    try:
        region = event["TopicArn"].split(":")[3]
        print(f"Event in region {region}")
    except (AttributeError, IndexError, KeyError, TypeError) as e:
        pprint(queue_messages[0].body)
        print(e)
        return

    tmp_sg = os.environ.get("TMP_SG_GRP", "")
    asg = event.get("AutoScalingGroupName")
    # This code only needs to run when the event is from the Controller ASG
    if (
        tmp_sg
        and os.environ.get("STATE", "") != "INIT"
        and asg == os.environ.get("CTRL_ASG")
    ):
        print("ECS probably did not complete last time. Trying to revert sg %s" % tmp_sg)
        restored_access = restore_security_group_access(ec2_client, tmp_sg, ecs_client)
        if restored_access:
            update_env_dict(ecs_client, {"TMP_SG_GRP": ""})
            update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": ""})

    try:
        msg_json = json.loads(event["Message"])
        msg_asg = msg_json.get("AutoScalingGroupName", "")
        msg_lifecycle = msg_json.get("LifecycleTransition", "")
        msg_desc = msg_json.get("Description", "")
        # https://docs.aws.amazon.com/autoscaling/ec2/userguide/warm-pools-eventbridge-events.html
        msg_orig = msg_json.get("Origin", "")
        msg_dest = msg_json.get("Destination", "")
        msg_inst = msg_json.get("EC2InstanceId", "")
        msg_event = msg_json.get("Event", "")

    except (KeyError, IndexError, ValueError) as err:
        raise AvxError("Could not parse message %s" % str(err)) from err

    print(f"Event {msg_lifecycle} Description {msg_desc}")

    # log copilot failover status
    try:
        cp_lib.log_failover_status("copilot")
    except Exception as err:
        print(f"Logging copilot failover status failed: {str(err)}")

    if msg_event == "autoscaling:TEST_NOTIFICATION":
        print("Successfully received Test Event from ASG")
    # Use PRIV_IP to determine if this is the intial deployment. Don't handle INTER_REGION on initial deploy.
    elif (
        os.environ.get("INTER_REGION") == "True"
        and msg_asg == os.environ.get("CTRL_ASG")
        and os.environ.get("PRIV_IP")
    ):
        pri_region = region
        dr_region = os.environ.get("DR_REGION")
        update_env_dict(ecs_client, {"CONTROLLER_RUNNING": "running"})
        handle_ctrl_inter_region_event(pri_region, dr_region)
        update_env_dict(ecs_client, {"CONTROLLER_RUNNING": ""})
        if aws_utils.get_task_def_env(ecs_client).get("COPILOT_RUNNING", "") == "":
                update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": "", "COP_TMP_SG_GRP": ""})
    elif msg_event == "autoscaling:EC2_INSTANCE_LAUNCHING_ERROR":
        print("Instance launch error, refer to logs for failure reason ")

    if msg_lifecycle == "autoscaling:EC2_INSTANCE_LAUNCHING":
        if msg_orig == "EC2" and msg_dest == "AutoScalingGroup":
            print("New instance launched into AutoscalingGroup")
        elif msg_orig == "EC2" and msg_dest == "WarmPool":
            print("New instance launched into WarmPool")
        elif msg_orig == "WarmPool" and msg_dest == "AutoScalingGroup":
            print("Failover event..Instance moving from WarmPool into AutoScaling")
        else:
            print(f"Unknown instance launch origin {msg_orig} and/or dest {msg_dest}")

        if msg_asg == os.environ.get("CTRL_ASG"):
            update_env_dict(ecs_client, {"CONTROLLER_RUNNING": "running"})
            handle_ctrl_ha_event(
                ec2_client,
                ecs_client,
                event,
                msg_inst,
                msg_orig,
                msg_dest,
            )
            update_env_dict(ecs_client, {"CONTROLLER_RUNNING": ""})
            if aws_utils.get_task_def_env(ecs_client).get("COPILOT_RUNNING", "") == "":
                update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": "", "COP_TMP_SG_GRP": ""})
        elif msg_asg == os.environ.get("COP_ASG"):
            update_env_dict(ecs_client, {"COPILOT_RUNNING": "running"})
            handle_cop_ha_event(
                ec2_client,
                ecs_client,
                event,
                msg_inst,
                msg_orig,
                msg_dest,
            )
            update_env_dict(ecs_client, {"COPILOT_RUNNING": ""})
            if aws_utils.get_task_def_env(ecs_client).get("CONTROLLER_RUNNING", "") == "":
                update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": "", "COP_TMP_SG_GRP": ""})


def create_new_sg(client):
    """Creates a new security group"""

    instance_name = os.environ.get("AVIATRIX_TAG")
    vpc_id = os.environ.get("VPC_ID")

    try:
        resp = client.create_security_group(
            Description="Aviatrix Controller", GroupName=instance_name, VpcId=vpc_id
        )
        sg_id = resp["GroupId"]
    except (botocore.exceptions.ClientError, KeyError) as err:
        if "InvalidGroup.Duplicate" in str(err):
            rsp = client.describe_security_groups(GroupNames=[instance_name])
            sg_id = rsp["SecurityGroups"][0]["GroupId"]
        else:
            raise AvxError(str(err)) from err

    try:
        client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )
    except botocore.exceptions.ClientError as err:
        if "InvalidGroup.Duplicate" in str(err) or "InvalidPermission.Duplicate" in str(
            err
        ):
            pass
        else:
            raise AvxError(str(err)) from err
    return sg_id


def update_env_dict(ecs_client, replace_dict={}):
    """Update particular variables in the Environment variables in ECS"""

    current_task_def = aws_utils.get_task_def(ecs_client)
    task_def_env_dict = aws_utils.get_task_def_env(ecs_client)

    env_dict = {
        "API_PRIVATE_ACCESS": os.environ.get("API_PRIVATE_ACCESS", "False"),
        "AVIATRIX_COP_TAG": os.environ.get("AVIATRIX_COP_TAG"),
        "AVIATRIX_TAG": os.environ.get("AVIATRIX_TAG"),
        "AVX_CUSTOMER_ID": os.environ.get("AVX_CUSTOMER_ID", ""),
        "AVX_CUSTOMER_ID_SSM_PATH": os.environ.get("AVX_CUSTOMER_ID_SSM_PATH"),
        "AVX_CUSTOMER_ID_SSM_REGION": os.environ.get("AVX_CUSTOMER_ID_SSM_REGION"),
        "AVX_PASSWORD": os.environ.get("AVX_PASSWORD", ""),
        "AVX_COP_PASSWORD": os.environ.get("AVX_COP_PASSWORD", ""),
        "AVX_PASSWORD_SSM_PATH": os.environ.get("AVX_PASSWORD_SSM_PATH"),
        "AVX_COPILOT_PASSWORD_SSM_PATH": os.environ.get(
            "AVX_COPILOT_PASSWORD_SSM_PATH"
        ),
        "AVX_PASSWORD_SSM_REGION": os.environ.get("AVX_PASSWORD_SSM_REGION"),
        "AWS_ROLE_APP_NAME": os.environ.get("AWS_ROLE_APP_NAME"),
        "AWS_ROLE_EC2_NAME": os.environ.get("AWS_ROLE_EC2_NAME"),
        "COP_ASG": os.environ.get("COP_ASG"),
        "COP_EIP": os.environ.get("COP_EIP"),
        "COP_DEPLOYMENT": os.environ.get("COP_DEPLOYMENT"),
        "COP_DATA_NODES_DETAILS": os.environ.get("COP_DATA_NODES_DETAILS"),
        "COP_EMAIL": os.environ.get("COP_EMAIL", ""),
        "COP_USERNAME": os.environ.get("COP_USERNAME", ""),
        "COP_AUTH_IP": os.environ.get("COP_AUTH_IP", ""),
        "CTRL_ASG": os.environ.get("CTRL_ASG"),
        "DISKS": os.environ.get("DISKS", ""),
        "EIP": os.environ.get("EIP"),
        "INST_ID": os.environ.get("INST_ID", ""),
        "INTER_REGION": os.environ.get("INTER_REGION"),
        "PRIV_IP": task_def_env_dict.get("PRIV_IP", ""),
        "S3_BUCKET_BACK": os.environ.get("S3_BUCKET_BACK"),
        "S3_BUCKET_REGION": os.environ.get("S3_BUCKET_REGION"),
        "SQS_QUEUE_NAME": os.environ.get("SQS_QUEUE_NAME"),
        "SQS_QUEUE_REGION": os.environ.get("SQS_QUEUE_REGION"),
        "TAGS": os.environ.get("TAGS", "[]"),
        "TMP_SG_GRP": os.environ.get("TMP_SG_GRP", ""),
        "COP_TMP_SG_GRP": task_def_env_dict.get("COP_TMP_SG_GRP", ""), # update from task_def_env
        "CONTROLLER_TMP_SG_GRP": task_def_env_dict.get("CONTROLLER_TMP_SG_GRP", ""), # update from task_def_env
        "CONTROLLER_RUNNING": task_def_env_dict.get("CONTROLLER_RUNNING", ""), # update from task_def_env
        "COPILOT_RUNNING": task_def_env_dict.get("COPILOT_RUNNING", ""), # update from task_def_env
        "VERSION": VERSION,
        "VPC_ID": os.environ.get("VPC_ID"),
        "PRIMARY_ACC_NAME": os.environ.get("PRIMARY_ACC_NAME"),
    }
    if os.environ.get("INTER_REGION") == "True":
        env_dict["ACTIVE_REGION"] = os.environ.get("ACTIVE_REGION")
        env_dict["ADMIN_EMAIL"] = os.environ.get("ADMIN_EMAIL")
        env_dict["CTRL_INIT_VER"] = os.environ.get("CTRL_INIT_VER", "")
        env_dict["DR_REGION"] = os.environ.get("DR_REGION")
        env_dict["INTER_REGION_BACKUP_ENABLED"] = os.environ.get(
            "INTER_REGION_BACKUP_ENABLED"
        )
        env_dict["RECORD_NAME"] = os.environ.get("RECORD_NAME")
        env_dict["STANDBY_REGION"] = os.environ.get("STANDBY_REGION")
        env_dict["ZONE_NAME"] = os.environ.get("ZONE_NAME")

    env_dict.update(replace_dict)
    os.environ.update(replace_dict)
    print("Updating environment %s" % env_dict)

    new_task_def = copy.deepcopy(current_task_def["taskDefinition"])

    remove_args = [
        "compatibilities",
        "registeredAt",
        "registeredBy",
        "status",
        "revision",
        "taskDefinitionArn",
        "requiresAttributes",
    ]
    for arg in remove_args:
        new_task_def.pop(arg)

    new_env_list = []
    for name, value in env_dict.items():
        new_env_list.append({"name": name, "value": value})

    new_task_def["containerDefinitions"][0]["environment"] = new_env_list
    new_task_def["tags"] = current_task_def["tags"]

    print("Updating task definition")
    ecs_client.register_task_definition(**new_task_def)
    print("Updated environment dictionary")


def sync_env_var(ecs_client, env_dict, replace_dict={}):
    """Update DR environment variables in ECS"""

    env_dict.update(replace_dict)

    print("Updating environment %s" % env_dict)
    current_task_def = aws_utils.get_task_def(ecs_client)

    new_task_def = copy.deepcopy(current_task_def["taskDefinition"])

    remove_args = [
        "compatibilities",
        "registeredAt",
        "registeredBy",
        "status",
        "revision",
        "taskDefinitionArn",
        "requiresAttributes",
    ]
    for arg in remove_args:
        new_task_def.pop(arg)

    new_env_list = []
    for name, value in env_dict.items():
        new_env_list.append({"name": name, "value": value})
    new_task_def["containerDefinitions"][0]["environment"] = new_env_list
    new_task_def["tags"] = current_task_def["tags"]

    print("Updating task definition")
    ecs_client.register_task_definition(**new_task_def)
    print("Updated environment dictionary")


def get_api_token(ip_addr):
    """Get API token from controller. Older controllers that don't support it will not have this
    API or endpoints. We return None in that scenario to be backkward compatible"""
    try:
        data = requests.get(
            f"https://{ip_addr}/v2/api?action=get_api_token", verify=False
        )
    except requests.exceptions.ConnectionError as err:
        print("Can't connect to controller with IP %s. %s" % (ip_addr, str(err)))
        raise AvxError(str(err)) from err
    buf = data.content
    if data.status_code not in [200, 404]:
        err = f"Controller at {ip_addr} is not ready. Status code {data.status_code}  {buf}"
        print(err)
        raise AvxError(err)
    try:
        out = json.loads(buf)
    except ValueError:
        print(f"Token is probably not supported. Response is {buf}")
        print("Did not obtain token")
        return None
    try:
        api_return = out["return"]
    except (KeyError, AttributeError, TypeError) as err:
        print(
            f"Getting return code failed due to {err}. Token may not be supported."
            f"Response is {out}"
        )
        print("Did not obtain token")
        return None
    if api_return is False:
        try:
            reason = out["reason"]
        except (KeyError, AttributeError, TypeError) as err:
            print(f"Couldn't get reason. Response is {out}")
            print("Did not obtain token")
            return None
        if reason == "RequestRefused":
            err = f"Controller at {ip_addr} is not ready. Status code {reason} {out}"
            print(err)
            raise AvxError(err)
        print(
            f"Getting token failed due to {reason}. Token may not be supported."
            f"Response is {out}"
        )
        print("Did not obtain token")
        return None
    try:
        token = out["results"]["api_token"]
    except (ValueError, AttributeError, TypeError, KeyError) as err:
        print(f"Getting token failed due to {err}")
        print(f"Token is probably not supported. Response is {out}")
        print("Did not obtain token")
        return None
    print("Obtained token")
    return token


def login_to_controller(ip_addr, username, pwd):
    """Logs into the controller and returns the cid"""
    token = get_api_token(ip_addr)
    headers = {}
    base_url = "https://" + ip_addr + "/v1/api"
    if token:
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Access-Key": token,
        }
        base_url = "https://" + ip_addr + "/v2/api"
    try:
        response = requests.post(
            base_url,
            verify=False,
            headers=headers,
            data={"username": username, "password": pwd, "action": "login"},
        )
    except Exception as err:
        print(
            "Can't connect to controller with elastic IP %s. %s" % (ip_addr, str(err))
        )
        raise AvxError(str(err)) from err
    try:
        response_json = response.json()
    except ValueError as err:
        print(f"response not in json {response}")
        raise AvxError("Unable to create session. {}".format(response)) from err
    try:
        cid = response_json.pop("CID")
        print("Created new session with CID {}\n".format(mask(cid)))
    except KeyError as err:
        print(response_json)
        print("Unable to create session. {} {}".format(err, response_json))
        raise AvxError("Unable to create session. {}".format(err)) from err
    print(response_json)
    return cid


def set_environ(client, ecs_client, controller_instanceobj, eip=None):
    """Sets Environment variables"""

    if eip is None:
        # If EIP is not known at this point, get from controller inst
        eip = controller_instanceobj["NetworkInterfaces"][0]["Association"].get(
            "PublicIp"
        )
    else:
        eip = os.environ.get("EIP")

    inst_id = controller_instanceobj["InstanceId"]
    vpc_id = controller_instanceobj["VpcId"]
    keyname = controller_instanceobj.get("KeyName", "")
    priv_ip = controller_instanceobj.get("NetworkInterfaces")[0].get("PrivateIpAddress")
    iam_arn = controller_instanceobj.get("IamInstanceProfile", {}).get("Arn", "")

    tags = controller_instanceobj.get("Tags", [])
    tags_stripped = []
    for tag in tags:
        key = tag.get("Key", "")
        # Tags starting with aws: is reserved
        if not key.startswith("aws:"):
            tags_stripped.append(tag)

    disks = []
    for volume in controller_instanceobj.get("BlockDeviceMappings", {}):
        ebs = volume.get("Ebs", {})
        if ebs.get("Status", "detached") == "attached":
            vol_id = ebs.get("VolumeId")
            vol = client.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]
            disks.append(
                {
                    "VolumeId": vol_id,
                    "DeleteOnTermination": ebs.get("DeleteOnTermination"),
                    "VolumeType": vol["VolumeType"],
                    "Size": vol["Size"],
                    "Iops": vol.get("Iops", ""),
                    "Encrypted": vol["Encrypted"],
                }
            )
    task_def_env_dict = aws_utils.get_task_def_env(ecs_client)

    env_dict = {
        "ADMIN_EMAIL": os.environ.get("ADMIN_EMAIL", ""),
        "PRIMARY_ACC_NAME": os.environ.get("PRIMARY_ACC_NAME", ""),
        "CTRL_INIT_VER": os.environ.get("CTRL_INIT_VER", ""),
        "EIP": eip,
        "COP_EIP": os.environ.get("COP_EIP"),
        "COP_DEPLOYMENT": os.environ.get("COP_DEPLOYMENT"),
        "COP_DATA_NODES_DETAILS": os.environ.get("COP_DATA_NODES_DETAILS"),
        "VPC_ID": vpc_id,
        "AVIATRIX_TAG": os.environ.get("AVIATRIX_TAG"),
        "AVIATRIX_COP_TAG": os.environ.get("AVIATRIX_COP_TAG"),
        "CTRL_ASG": os.environ.get("CTRL_ASG"),
        "COP_ASG": os.environ.get("COP_ASG"),
        "API_PRIVATE_ACCESS": os.environ.get("API_PRIVATE_ACCESS", "False"),
        "PRIV_IP": priv_ip,
        "INST_ID": inst_id,
        "S3_BUCKET_BACK": os.environ.get("S3_BUCKET_BACK"),
        "S3_BUCKET_REGION": os.environ.get("S3_BUCKET_REGION", ""),
        "DISKS": json.dumps(disks),
        "TAGS": json.dumps(tags_stripped),
        "TMP_SG_GRP": os.environ.get("TMP_SG_GRP", ""),
        "COP_TMP_SG_GRP": task_def_env_dict.get("COP_TMP_SG_GRP", ""), # update from task_def_env
        "CONTROLLER_TMP_SG_GRP": task_def_env_dict.get("CONTROLLER_TMP_SG_GRP", ""), # update from task_def_env
        "CONTROLLER_RUNNING": task_def_env_dict.get("CONTROLLER_RUNNING", ""), # update from task_def_env
        "COPILOT_RUNNING": task_def_env_dict.get("COPILOT_RUNNING", ""), # update from task_def_env
        "AWS_ROLE_APP_NAME": os.environ.get("AWS_ROLE_APP_NAME"),
        "AWS_ROLE_EC2_NAME": os.environ.get("AWS_ROLE_EC2_NAME"),
        "INTER_REGION": os.environ.get("INTER_REGION"),
        "SQS_QUEUE_NAME": os.environ.get("SQS_QUEUE_NAME"),
        "SQS_QUEUE_REGION": os.environ.get("SQS_QUEUE_REGION"),
        "AVX_CUSTOMER_ID": os.environ.get("AVX_CUSTOMER_ID", ""),
        "AVX_CUSTOMER_ID_SSM_PATH": os.environ.get("AVX_CUSTOMER_ID_SSM_PATH"),
        "AVX_CUSTOMER_ID_SSM_REGION": os.environ.get("AVX_CUSTOMER_ID_SSM_REGION"),
        "AVX_PASSWORD": os.environ.get("AVX_PASSWORD", ""),
        "AVX_COP_PASSWORD": os.environ.get("AVX_COP_PASSWORD", ""),
        "AVX_PASSWORD_SSM_PATH": os.environ.get("AVX_PASSWORD_SSM_PATH"),
        "AVX_COPILOT_PASSWORD_SSM_PATH": os.environ.get("AVX_COPILOT_PASSWORD_SSM_PATH", ""),
        "AVX_PASSWORD_SSM_REGION": os.environ.get("AVX_PASSWORD_SSM_REGION", ""),
        "COP_USERNAME": os.environ.get("COP_USERNAME", ""),
        "COP_AUTH_IP": os.environ.get("COP_AUTH_IP", ""),
        "COP_EMAIL": os.environ.get("COP_EMAIL", ""),
        "VERSION": VERSION,
    }
    if os.environ.get("INTER_REGION") == "True":
        env_dict["DR_REGION"] = os.environ.get("DR_REGION")
        env_dict["ACTIVE_REGION"] = os.environ.get("ACTIVE_REGION")
        env_dict["STANDBY_REGION"] = os.environ.get("STANDBY_REGION")
        env_dict["ZONE_NAME"] = os.environ.get("ZONE_NAME")
        env_dict["RECORD_NAME"] = os.environ.get("RECORD_NAME")
        env_dict["INTER_REGION_BACKUP_ENABLED"] = os.environ.get(
            "INTER_REGION_BACKUP_ENABLED"
        )
    print("Setting environment %s" % env_dict)
    current_task_def = aws_utils.get_task_def(ecs_client)
    new_task_def = copy.deepcopy(current_task_def["taskDefinition"])

    remove_args = [
        "compatibilities",
        "registeredAt",
        "registeredBy",
        "status",
        "revision",
        "taskDefinitionArn",
        "requiresAttributes",
    ]
    for arg in remove_args:
        new_task_def.pop(arg)

    new_env_list = []
    for name, value in env_dict.items():
        new_env_list.append({"name": name, "value": value})

    new_task_def["containerDefinitions"][0]["environment"] = new_env_list
    new_task_def["tags"] = current_task_def["tags"]

    print("Updating task definition")
    ecs_client.register_task_definition(**new_task_def)
    os.environ.update(env_dict)


def verify_iam(controller_instanceobj):
    """Verify IAM roles"""

    print("Verifying IAM roles ")
    iam_arn = controller_instanceobj.get("IamInstanceProfile", {}).get("Arn", "")
    if not iam_arn:
        return False
    return True


def verify_bucket(controller_instanceobj):
    """Verify S3 and Controller account credentials"""

    print("Verifying bucket")
    try:
        s3_client = boto3.client("s3")
        resp = s3_client.get_bucket_location(Bucket=os.environ.get("S3_BUCKET_BACK"))
    except Exception as err:
        print(f"S3 bucket used for backup is not valid. {str(err)}")
        return False, ""

    try:
        bucket_region = resp["LocationConstraint"]

        # Buckets in Region us-east-1 have a LocationConstraint of null
        if bucket_region is None:
            print(f"Bucket region is None. Setting to {AWS_US_EAST_REGION}")
            bucket_region = AWS_US_EAST_REGION
    except KeyError:
        print(
            "Key LocationConstraint not found in get_bucket_location response %s" % resp
        )
        return False, ""

    print("S3 bucket is valid.")
    eip = controller_instanceobj["NetworkInterfaces"][0]["Association"].get("PublicIp")
    print(eip)

    return True, bucket_region


def is_region2_latest_backup_file(priv_ip, dr_priv_ip):
    """Check latest backup among two regions"""
    backup_file = f"CloudN_{priv_ip}_save_cloudx_config.enc"
    dr_backup_file = f"CloudN_{dr_priv_ip}_save_cloudx_config.enc"
    try:
        s3c = boto3.client("s3", region_name=os.environ["S3_BUCKET_REGION"])
        try:
            pri_file_obj = s3c.get_object(
                Key=backup_file, Bucket=os.environ.get("S3_BUCKET_BACK")
            )
        except Exception as err:
            pri_file_obj = ""
            print(f"{backup_file} not found in the container: {str(err)}")
        try:
            dr_file_obj = s3c.get_object(
                Key=dr_backup_file, Bucket=os.environ.get("S3_BUCKET_BACK")
            )
        except Exception as err:
            dr_file_obj = ""
            print(f"{dr_backup_file} not found in the container: {str(err)}")
        if pri_file_obj != "" and dr_file_obj == "":
            print(f"{backup_file} exist")
            return False
        elif pri_file_obj == "" and dr_file_obj != "":
            print(f"{dr_backup_file} exist")
            return True
        elif pri_file_obj != "" and dr_file_obj != "":
            print(
                f"Container has backups from both regions, so checking for latest backup among both the files"
            )
            pri_file_obj_age = pri_file_obj["LastModified"].timestamp()
            dr_file_obj_age = dr_file_obj["LastModified"].timestamp()
            if dr_file_obj_age > pri_file_obj_age:
                print(f"{backup_file} has the latest backup")
                return True
            else:
                print(f"{dr_backup_file} has the latest backup")
                return False
        else:
            raise AvxError("Backup doesn't exist from either regions")

    except Exception as err:
        raise AvxError(f"Checking which region has latest backup, Error: {str(err)}")


def is_backup_file_is_recent(backup_file):
    """Check if backup file is not older than MAXIMUM_BACKUP_AGE"""

    try:
        s3c = boto3.client("s3", region_name=os.environ["S3_BUCKET_REGION"])
        try:
            file_obj = s3c.get_object(
                Key=backup_file, Bucket=os.environ.get("S3_BUCKET_BACK")
            )
        except botocore.exceptions.ClientError as err:
            print(str(err))
            return False

        age = time.time() - file_obj["LastModified"].timestamp()
        if age < MAXIMUM_BACKUP_AGE:
            print("Succesfully validated Backup file age")
            return True
        print(
            f"File age {age} is older than the maximum allowed value of {MAXIMUM_BACKUP_AGE}"
        )
        return False
    except Exception as err:
        print(f"Checking backup file age failed due to {str(err)}")
        return False


def retrieve_controller_version(version_file, ip_addr="", cid=""):
    """Get the controller version from backup file"""

    print("Retrieving version from file " + str(version_file))
    s3c = boto3.client("s3", region_name=os.environ["S3_BUCKET_REGION"])
    try:
        with open("/tmp/version_ctrlha.txt", "wb") as data:
            s3c.download_fileobj(os.environ.get("S3_BUCKET_BACK"), version_file, data)
    except botocore.exceptions.ClientError as err:
        if err.response["Error"]["Code"] == "404":
            print("The object does not exist.")
            raise AvxError("The cloudx version file does not exist") from err
        raise

    if not os.path.exists("/tmp/version_ctrlha.txt"):
        raise AvxError("Unable to open version file")

    with open("/tmp/version_ctrlha.txt") as fileh:
        buf = fileh.read()
    print("Retrieved version " + str(buf))

    if not buf:
        raise AvxError("Version file is empty")

    print("Parsing version")
    if buf.startswith(VERSION_PREFIX):
        buf = buf[len(VERSION_PREFIX) :]

    try:
        ver_list = buf.split(".")
        ctrl_version = ".".join(ver_list[:-1])
        ctrl_version_with_build = ".".join(ver_list)
    except (KeyboardInterrupt, IndexError, ValueError) as err:
        raise AvxError("Could not decode version") from err
    else:
        print(f"Parsed version sucessfully {ctrl_version_with_build}")
        return ctrl_version_with_build


def controller_version(ip_addr, cid):
    """Check current build version"""

    print("Checking current version of the controller")
    base_url = "https://" + ip_addr + "/v1/api"
    post_data = {"CID": cid, "action": "list_version_info"}
    try:
        response = requests.post(base_url, data=post_data, verify=False)
        py_dict = response.json()
        if "CID" in py_dict:
            py_dict["CID"] = "*********"
        print(f"Aviatrix API response is: {py_dict}")

        buf = py_dict["results"]["current_version"]
        try:
            ctrl_version = ".".join((buf[12:]).split("."))
        except (KeyboardInterrupt, IndexError, ValueError) as err:
            raise AvxError("Could not decode version from the controller") from err
        else:
            print(f"Parsed version sucessfully {ctrl_version}")
            return ctrl_version

    except Exception as err:
        print(f"Error occurred while fetching controller version: {str(err)}")
        raise


def upgrade_controller(ip_addr, cid, version=None):
    """Upgrade build version"""

    print("Upgrading controller version")
    base_url = "https://" + ip_addr + "/v1/api"
    post_data = {"CID": cid, "action": "upgrade", "version": version}
    try:
        response = requests.post(base_url, data=post_data, verify=False)
        py_dict = response.json()
        if "CID" in py_dict:
            py_dict["CID"] = "*********"
        print(f"Aviatrix API response is: {py_dict}")

    except requests.Timeout:
        print("Upgrading controller timed out. ")
        pass
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print(
                "Server closed the connection while executing "
                "create account API. Ignoring response"
            )
            output = {
                "return": True,
                "reason": "Warning!! Server closed the connection",
            }
            time.sleep(INITIAL_SETUP_WAIT)
        else:
            output = {"return": False, "reason": str(err)}
    except Exception as err:
        print(f"An Error has occurred: {str(err)}")
        raise
    else:
        output = response.json()
        print(output)
        return output


def get_initial_setup_status(ip_addr, cid):
    """Get status of the initial setup completion execution"""

    print("Checking initial setup")
    base_url = "https://" + ip_addr + "/v1/api"
    post_data = {"CID": cid, "action": "initial_setup", "subaction": "check"}

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        print(str(err))
        return {"return": False, "reason": str(err)}
    return response.json()


def run_initial_setup(ip_addr, cid, ctrl_version):
    """Boots the fresh controller to the specific version"""

    response_json = get_initial_setup_status(ip_addr, cid)
    if response_json.get("return") is True:
        print("Initial setup is already done. Skipping")
        return True

    post_data = {
        "target_version": ctrl_version,
        "action": "initial_setup",
        "subaction": "run",
    }
    print("Trying to run initial setup %s\n" % str(post_data))
    post_data["CID"] = cid
    base_url = "https://" + ip_addr + "/v1/api"

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print(
                "Server closed the connection while executing initial setup API."
                " Ignoring response"
            )
            response_json = {
                "return": True,
                "reason": "Warning!! Server closed the connection",
            }
        else:
            raise AvxError("Failed to execute initial setup: " + str(err)) from err
    else:
        response_json = response.json()
        # Controllers running 6.4 and above would be unresponsive after initial_setup

    print(response_json)

    time.sleep(INITIAL_SETUP_API_WAIT)

    if response_json.get("return") is True:
        print("Successfully initialized the controller")
    else:
        raise AvxError(
            "Could not bring up the new controller to the " "specific version"
        )
    return False


def temp_add_security_group_access(client, controller_instanceobj, api_private_access):
    """Temporarily add 0.0.0.0/0 rule in one security group"""

    sgs = [sg_["GroupId"] for sg_ in controller_instanceobj["SecurityGroups"]]
    if api_private_access == "True":
        return True, sgs[0]

    if not sgs:
        raise AvxError("No security groups were attached to controller")

    try:
        client.authorize_security_group_ingress(
            GroupId=sgs[0],
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
    except botocore.exceptions.ClientError as err:
        if "InvalidPermission.Duplicate" in str(err):
            return True, sgs[0]

        print(str(err))
        raise

    return False, sgs[0]


def restore_security_group_access(client, sg_id, ecs_client):
    """Remove 0.0.0.0/0 rule in previously added security group"""

    if aws_utils.get_task_def_env(ecs_client).get("COPILOT_RUNNING", "") == "running":
        print(f"Abort SG restore - COPILOT_RUNNING is set")
        return

    try:
        client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
    except botocore.exceptions.ClientError as err:
        if "InvalidPermission.NotFound" not in str(err) and "InvalidGroup" not in str(
            err
        ):
            print(str(err))


def handle_login_failure(priv_ip, client, ecs_client, controller_instanceobj, eip, cid):
    """Handle login failure through private IP"""

    print("Checking for backup file")
    new_version_file = "CloudN_" + priv_ip + "_save_cloudx_version.txt"

    try:
        retrieve_controller_version(new_version_file, priv_ip, cid)
    except Exception as err:
        print(str(err))
        print(
            "Could not retrieve new version file. Stopping instance. ASG will terminate and "
            "launch a new instance"
        )
        inst_id = controller_instanceobj["InstanceId"]
        print(f"Stopping {inst_id}")
        client.stop_instances(InstanceIds=[inst_id])
    else:
        print(
            "Successfully retrieved version. Previous restore operation had succeeded. "
            "Previous ECS may have exceeded 5 min. Updating ECS config"
        )
        set_environ(client, ecs_client, controller_instanceobj, eip)


def get_role(role, default):
    name = os.environ.get(role)
    if len(name) == 0:
        return default
    return name


def create_cloud_account(cid, controller_ip, account_name):
    """Create a temporary account to restore the backup"""

    print(f"Creating {account_name} account")
    client = boto3.client("sts")
    ec2_client = boto3.client("ec2")
    region_list = ec2_client.describe_regions()['Regions']
 
    aws_acc_num = client.get_caller_identity()["Account"]
    base_url = "https://%s/v1/api" % controller_ip
 
    # if re.match("^cn-", region_list[0]["RegionName"]) != None:
    if region_list[0]["RegionName"].startswith("cn-") == True:
        print("cn- identification is true")
        post_data = {
        "action": "setup_account_profile",
        "account_name": account_name,
        "aws_china_account_number": aws_acc_num,
        "aws_china_role_arn": "arn:aws-cn:iam::%s:role/%s"
        % (aws_acc_num, get_role("AWS_ROLE_APP_NAME", "aviatrix-role-app")),
        "aws_china_role_ec2": "arn:aws-cn:iam::%s:role/%s"
        % (aws_acc_num, get_role("AWS_ROLE_EC2_NAME", "aviatrix-role-ec2")),
        "cloud_type": "1024",
        "aws_china_iam": "true",
    }
    else:
        print("cn- identification is false")
        post_data = {
        "action": "setup_account_profile",
        "account_name": account_name,
        "aws_account_number": aws_acc_num,
        "aws_role_arn": "arn:aws:iam::%s:role/%s"
        % (aws_acc_num, get_role("AWS_ROLE_APP_NAME", "aviatrix-role-app")),
        "aws_role_ec2": "arn:aws:iam::%s:role/%s"
        % (aws_acc_num, get_role("AWS_ROLE_EC2_NAME", "aviatrix-role-ec2")),
        "cloud_type": "1",
        "aws_iam": "true",
    }
                    
    print("Trying to create account with data %s\n" % str(post_data))
    post_data["CID"] = cid

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print(
                "Server closed the connection while executing create account API."
                " Ignoring response"
            )
            output = {
                "return": True,
                "reason": "Warning!! Server closed the connection",
            }
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()

    return output


def restore_backup(cid, controller_ip, s3_file, account_name):
    """Restore backup from the s3 bucket"""
    ec2_client = boto3.client("ec2")
    region_list = ec2_client.describe_regions().get('Regions')
    if region_list[0]["RegionName"].startswith("cn-"):
        cloud_type = "1024"
    else:
        cloud_type = "1"
    restore_data = {
        "action": "restore_cloudx_config",
        "cloud_type": cloud_type,
        "account_name": account_name,
        "file_name": s3_file,
        "bucket_name": os.environ.get("S3_BUCKET_BACK"),
    }

    print("Trying to restore config with data %s\n" % str(restore_data))
    restore_data["CID"] = cid
    base_url = "https://" + controller_ip + "/v1/api"

    try:
        response = requests.post(base_url, data=restore_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print(
                "Server closed the connection while executing restore_cloudx_config API."
                " Ignoring response"
            )
            response_json = {
                "return": True,
                "reason": "Warning!! Server closed the connection",
            }
        else:
            print(str(err))
            response_json = {"return": False, "reason": str(err)}
    else:
        response_json = response.json()

    return response_json


def is_controller_ready_v2(
    ip_addr="123.123.123.123",
    CID="ABCD1234",
):
    start_time = time.time()
    api_endpoint_url = "https://" + ip_addr + "/v2/api"
    data = {"action": "is_controller_ready", "CID": CID}
    print("API endpoint url: %s", str(api_endpoint_url))
    payload_with_hidden_password = dict(data)
    payload_with_hidden_password["CID"] = "************"
    print(
        f"Request payload: "
        f"{str(json.dumps(obj=payload_with_hidden_password, indent=4))}"
    )

    while time.time() - start_time < 600:
        try:
            response = requests.get(
                url=api_endpoint_url, params=data, verify=False, timeout=60
            )
            if response is not None:
                py_dict = response.json()

                if response.status_code == 200 and py_dict["return"] is True:
                    print(f"Controller is ready to operate")
                    return True
                    break
            else:
                print(f"Controller is not ready")
        except requests.Timeout:
            print(f"The API request timed out after 60 seconds")
        except Exception as err:
            print(str(err))
        print(f"Checking if controller is ready in 60 seconds.")
        time.sleep(60)

    print(f"Controller is not ready to operate")
    return False


def set_customer_id(cid, controller_api_ip):
    """Set the customer ID if set in environment to migrate to a different AMI type"""

    print("Setting up Customer ID")
    if os.environ.get("AVX_CUSTOMER_ID", "") == "":
        customer_id = get_ssm_parameter_value(
            os.environ.get("AVX_CUSTOMER_ID_SSM_PATH"),
            os.environ.get("AVX_CUSTOMER_ID_SSM_REGION"),
        )
    else:
        customer_id = os.environ.get("AVX_CUSTOMER_ID", "")

    base_url = "https://" + controller_api_ip + "/v1/api"
    post_data = {
        "CID": cid,
        "action": "setup_customer_id",
        "customer_id": customer_id,
    }

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print(
                "Server closed the connection while executing setup_customer_id API."
                " Ignoring response"
            )
            response_json = {
                "return": True,
                "reason": "Warning!! Server closed the connection",
            }
            time.sleep(WAIT_DELAY)
        else:
            response_json = {"return": False, "reason": str(err)}
    else:
        response_json = response.json()

    if response_json.get("return") is True:
        print("Customer ID successfully programmed")
    else:
        print(
            "Customer ID programming failed. DB restore will fail: "
            + response_json.get("reason", "")
        )


def setup_ctrl_backup(controller_ip, cid, acc_name, now=None):
    """Enable S3 backup"""
    ec2_client = boto3.client("ec2")
    region_list = ec2_client.describe_regions().get('Regions')
    if region_list[0]["RegionName"].startswith("cn-"):
        cloud_type = "1024"
    else:
        cloud_type = "1"

    base_url = "https://%s/v1/api" % controller_ip

    post_data = {
        "action": "enable_cloudn_backup_config",
        "CID": cid,
        "cloud_type": cloud_type,
        "account_name": acc_name,
        "bucket_name": os.environ.get("S3_BUCKET_BACK"),
        "multiple": "true",
        "region": os.environ.get("S3_BUCKET_REGION"),
        "now": now,
    }

    print("Creating S3 backup: " + str(json.dumps(obj=post_data)))

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print(
                "Server closed the connection while executing create account API."
                " Ignoring response"
            )
            output = {
                "return": True,
                "reason": "Warning!! Server closed the connection",
            }
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()

    return output


def set_admin_email(controller_ip, cid, admin_email):
    """ "add_admin_email_addr" API is supported by all controller versions since 2.6"""

    base_url = "https://%s/v1/api" % controller_ip
    post_data = {
        "action": "add_admin_email_addr",
        "CID": cid,
        "admin_email": admin_email,
    }

    payload_with_hidden_password = dict(post_data)
    payload_with_hidden_password["CID"] = "*********"

    print("Setting admin email: " + str(json.dumps(obj=payload_with_hidden_password)))

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print(
                "Server closed the connection while executing create account API."
                " Ignoring response"
            )
            output = {
                "return": True,
                "reason": "Warning!! Server closed the connection",
            }
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()

    return output


def get_ssm_parameter_value(path, region):
    try:
        ssm_client = boto3.client("ssm", region)
        resp = ssm_client.get_parameter(Name=path, WithDecryption=True)
        return resp["Parameter"]["Value"]
    except Exception as err:
        raise AvxError(f"Error fetching from ssm")


def set_admin_password(controller_ip, cid, old_admin_password):
    """Set admin password"""

    if os.environ.get("AVX_PASSWORD", "") == "":
        # Fetch Aviatrix Controller credentials from encrypted SSM parameter store
        ssm_client = boto3.client("ssm", os.environ.get("AVX_PASSWORD_SSM_REGION"))
        resp = ssm_client.get_parameter(
            Name=os.environ.get("AVX_PASSWORD_SSM_PATH"), WithDecryption=True
        )
        new_admin_password = resp["Parameter"]["Value"]
    else:
        new_admin_password = os.environ.get("AVX_PASSWORD", "")

    base_url = "https://%s/v1/api" % controller_ip

    post_data = {
        "action": "change_password",
        "CID": cid,
        "account_name": "admin",
        "user_name": "admin",
        "old_password": old_admin_password,
        "password": new_admin_password,
    }

    payload_with_hidden_password = dict(post_data)
    payload_with_hidden_password["password"] = "************"
    payload_with_hidden_password["CID"] = "*********"

    print(
        "Setting admin password: " + str(json.dumps(obj=payload_with_hidden_password))
    )

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print(
                "Server closed the connection while executing create account API."
                " Ignoring response"
            )
            output = {
                "return": True,
                "reason": "Warning!! Server closed the connection",
            }
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()

    return output


# Given an ASG name, returns the DNS Name of the LB
def get_lb_dns_name(asg_name, region):
    as_client = boto3.client("autoscaling", region_name=region)
    elb_client = boto3.client("elbv2", region_name=region)

    response = as_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    target_group_arns = response["AutoScalingGroups"][0]["TargetGroupARNs"]
    response = elb_client.describe_target_groups(TargetGroupArns=target_group_arns)
    lb_arns = response["TargetGroups"][0]["LoadBalancerArns"]
    response = elb_client.describe_load_balancers(LoadBalancerArns=lb_arns)
    lb_dns_name = response["LoadBalancers"][0]["DNSName"]
    return lb_dns_name


# Given an ASG name, returns the hosted zone ID of the LB
def get_lb_hosted_zone_id(asg_name, region):
    as_client = boto3.client("autoscaling", region_name=region)
    elb_client = boto3.client("elbv2", region_name=region)

    response = as_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    target_group_arns = response["AutoScalingGroups"][0]["TargetGroupARNs"]
    response = elb_client.describe_target_groups(TargetGroupArns=target_group_arns)
    lb_arns = response["TargetGroups"][0]["LoadBalancerArns"]
    response = elb_client.describe_load_balancers(LoadBalancerArns=lb_arns)
    lb_hosted_zone_id = response["LoadBalancers"][0]["CanonicalHostedZoneId"]
    return lb_hosted_zone_id


def update_record(zone_name, record_name, asg_name, region):
    route53_client = boto3.client("route53")

    # Get the hosted zone ID
    response = route53_client.list_hosted_zones_by_name(DNSName=zone_name)
    hosted_zone_id = response["HostedZones"][0]["Id"]

    # Get LB hosted zone id and dns name
    lb_hosted_zone_id = get_lb_hosted_zone_id(asg_name, region)
    lb_dns_name = get_lb_dns_name(asg_name, region)

    # Update Route 53
    response = route53_client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "A",
                        "AliasTarget": {
                            "HostedZoneId": lb_hosted_zone_id,
                            "DNSName": lb_dns_name,
                            "EvaluateTargetHealth": False,
                        },
                    },
                }
            ]
        },
    )


def handle_ctrl_inter_region_event(pri_region, dr_region):
    start_time = time.time()
    # 1. Fetching all env variables in between regions
    pri_client = boto3.client("ec2", pri_region)
    pri_ecs_client = boto3.client("ecs", pri_region)
    dr_client = boto3.client("ec2", dr_region)
    dr_ecs_client = boto3.client("ecs", dr_region)
    pri_env_var = pri_ecs_client.describe_task_definition(
        taskDefinition=TASK_DEF_FAMILY
    )["taskDefinition"]["containerDefinitions"][0]["environment"]
    dr_env_var = dr_ecs_client.describe_task_definition(taskDefinition=TASK_DEF_FAMILY)[
        "taskDefinition"
    ]["containerDefinitions"][0]["environment"]

    # Convert lists to dicts
    pri_env = {env_var["name"]: env_var["value"] for env_var in pri_env_var}
    dr_env = {env_var["name"]: env_var["value"] for env_var in dr_env_var}

    # 2. Trying to find Instance in DR region
    if dr_env.get("INST_ID"):
        print(f"INST_ID: {dr_env.get('INST_ID')}")
        dr_instanceobj = aws_utils.get_ec2_instance(dr_client, "", dr_env.get("INST_ID"))
    elif dr_env.get("AVIATRIX_TAG"):
        print(f"AVIATRIX_TAG : {dr_env.get('AVIATRIX_TAG')}")
        dr_instanceobj = aws_utils.get_ec2_instance(dr_client, dr_env.get("AVIATRIX_TAG"), "")
    else:
        dr_instanceobj = {}

    if dr_instanceobj == {}:
        raise AvxError(f"Cannot find Controller in {dr_region}")

    dr_private_ip = dr_instanceobj.get("NetworkInterfaces")[0].get("PrivateIpAddress")
    priv_ip = pri_env.get("PRIV_IP")
    print(f"Priv_ip : {priv_ip}")
    print(f"dr_private_ip : {dr_private_ip}")

    # 3. Trying to find Instance in DR region
    if is_region2_latest_backup_file(priv_ip, dr_private_ip):
        s3_file = "CloudN_" + dr_private_ip + "_save_cloudx_config.enc"
        version_file = "CloudN_" + dr_private_ip + "_save_cloudx_version.txt"
    else:
        s3_file = "CloudN_" + priv_ip + "_save_cloudx_config.enc"
        version_file = "CloudN_" + priv_ip + "_save_cloudx_version.txt"

    dr_api_ip = dr_instanceobj["PublicIpAddress"]
    print("DR API Access to Controller will use IP : " + str(dr_api_ip))
    api_private_access = dr_env["API_PRIVATE_ACCESS"]

    # 4. Temp security group access
    dr_duplicate, dr_sg_modified = temp_add_security_group_access(
        dr_client, dr_instanceobj, api_private_access
    )
    if not dr_duplicate:
        update_env_dict(dr_ecs_client, {"CONTROLLER_TMP_SG_GRP": dr_sg_modified})
        print(f"created tmp access - updated CONTROLLER_TMP_SG_GRP: {os.environ.items()}")
    print(
        "0.0.0.0/0:443 rule is %s present %s"
        % (
            "already" if dr_duplicate else "not",
            "" if dr_duplicate else ". Modified Security group %s" % dr_sg_modified,
        )
    )
    total_time = 0

    if os.environ.get("AVX_PASSWORD", "") == "":
        creds = get_ssm_parameter_value(
            os.environ.get("AVX_PASSWORD_SSM_PATH"),
            os.environ.get("AVX_PASSWORD_SSM_REGION"),
        )
    else:
        creds = os.environ.get("AVX_PASSWORD", "")

    # Check if this is the Active or Standby region
    if pri_region == pri_env.get("ACTIVE_REGION"):
        print("This event happened in the active region:", pri_env.get("ACTIVE_REGION"))

        try:
            if not dr_duplicate:
                sync_env_var(
                    dr_ecs_client,
                    dr_env,
                    {"TMP_SG_GRP": dr_sg_modified, "STATE": "INIT"},
                )
            else:
                sync_env_var(dr_ecs_client, dr_env, {"STATE": "INIT"})
            # while total_time <= MAX_LOGIN_TIMEOUT:
            while time.time() - start_time < HANDLE_HA_TIMEOUT:
                try:
                    cid = login_to_controller(dr_api_ip, "admin", creds)
                    s3_ctrl_version = retrieve_controller_version(
                        version_file, dr_api_ip, cid
                    )
                except Exception as err:
                    print(str(err))
                    print("Login failed, trying again in " + str(WAIT_DELAY))
                    total_time += WAIT_DELAY
                    time.sleep(WAIT_DELAY)
                else:
                    break

            # 5. Upgrade controller if needed
            if s3_ctrl_version != controller_version(dr_api_ip, cid):
                print(f"Upgrading controller to {s3_ctrl_version}")
                upgrade_controller(dr_api_ip, cid, s3_ctrl_version)

            # Restore controller
            cid = login_to_controller(dr_api_ip, "admin", creds)
            response_json = restore_backup(
                cid, dr_api_ip, s3_file, pri_env["PRIMARY_ACC_NAME"]
            )
            print(response_json)
            if response_json["return"] == True:
                failover = "completed"

            # 5. Migrate IP

            if s3_ctrl_version and int(s3_ctrl_version.split(".")[0]) >= 7:
                if is_controller_ready_v2(dr_api_ip, cid) == True:
                    print("START: Migrate IP")
                    migrate_ip(dr_api_ip, cid, pri_env["EIP"])
                    print("END: Migrate IP")
                else:
                    print(
                        "Controller is still restoring, migrate previous ip: %s manually"
                        % pri_env["EIP"]
                    )
            else:
                print(
                    "Once the restore process is completed, migrate previous ip: %s manually"
                    % pri_env["EIP"]
                )

            current_active_region = pri_env.get("ACTIVE_REGION")
            current_standby_region = pri_env.get("STANDBY_REGION")

            print(
                "Update ACTIVE_REGION & STANDBY_REGION in DR ECS environment variables"
            )
            sync_env_var(
                dr_ecs_client,
                dr_env,
                {
                    "ACTIVE_REGION": current_standby_region,
                    "STANDBY_REGION": current_active_region,
                },
            )

            print(
                "Update ACTIVE_REGION & STANDBY_REGION in primary ECS environment variables"
            )
            sync_env_var(
                pri_ecs_client,
                pri_env,
                {
                    "ACTIVE_REGION": current_standby_region,
                    "STANDBY_REGION": current_active_region,
                },
            )

            # Update environment so that ACTIVE_REGION and STANDBY_REGION are set correctly
            os.environ.update(
                {
                    "ACTIVE_REGION": current_standby_region,
                    "STANDBY_REGION": current_active_region,
                }
            )

            # Update Route 53
            update_record(
                pri_env.get("ZONE_NAME"),
                pri_env.get("RECORD_NAME"),
                pri_env.get("CTRL_ASG"),
                dr_region,
            )
            print(
                "Updating %s to point to the LB in %s"
                % (pri_env.get("RECORD_NAME"), dr_region)
            )

        finally:
            if s3_ctrl_version and s3_ctrl_version != dr_env.get("CTRL_INIT_VER"):
                init_ver = s3_ctrl_version
            else:
                init_ver = dr_env.get("CTRL_INIT_VER")
            if failover and failover == "completed":
                state = "ACTIVE"
            else:
                state = ""
            if not dr_duplicate:
                print(f"Reverting sg {dr_sg_modified}")
                restored_access = restore_security_group_access(dr_client, dr_sg_modified, dr_ecs_client)
                if restored_access:
                    update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": ""})
            sync_env_var(
                dr_ecs_client,
                dr_env,
                {"CTRL_INIT_VER": init_ver, "TMP_SG_GRP": "", "STATE": state},
            )
            print("- Completed function -")

    elif pri_region == pri_env.get("STANDBY_REGION"):
        print(
            "This event happened in the standby region:", pri_env.get("STANDBY_REGION")
        )


def handle_ctrl_ha_event(client, ecs_client, event, asg_inst, asg_orig, asg_dest):
    """Restores the backup by doing the following
    1. Login to new controller
    2. There are 3 cases depending on asg_orig and asg_dest. Note that
       asg_orig  and asg_dest are among (EC2, WarmPool, AutoScalingGroup)
        a) asg_orig = EC2 and asg_dest = AutoScalingGroup
            i)   Assign the EIP to the new Controller
            ii)  If first boot:
                - Run initial setup and boot to input version
                - Set admin email and password
                - Create primary AWS account
                - Setup S3 backup
            iii) For non-first case (priv_ip & backup exist):
                - Run initial setup and boot to version parsed from backup
                - Login and create temp AWS account
                - Restore configuration from backup
        b) asg_orig = EC2 and asg_dest = WarmPool
            i)  Update Name tag to indicate standby Controller
            ii) Run initial setup and boot to version parsed from backup
        c) asg_orig = WarmPool and asg_dest = AutoScalingGroup
            i)   Update Name tag to indicate standby instance is now active
            ii)  Assign the EIP to the new Controller
            iii) Login and create temp AWS account
            ii)  Restore configuration from backup
    """

    start_time = time.time()

    print(f"ASG event from origin {asg_orig} to destination {asg_dest}")
    if asg_orig == "EC2" and asg_dest == "WarmPool":
        warm_inst = True
        client.create_tags(
            Resources=[asg_inst],
            Tags=[
                {"Key": "Name", "Value": os.environ.get("AVIATRIX_TAG") + "(Standby)"}
            ],
        )

    if asg_orig == "WarmPool" and asg_dest == "AutoScalingGroup":
        client.create_tags(
            Resources=[asg_inst],
            Tags=[{"Key": "Name", "Value": os.environ.get("AVIATRIX_TAG")}],
        )

    old_inst_id = os.environ.get("INST_ID")
    print(f"Old instance ID = {old_inst_id}")
    if old_inst_id == asg_inst:
        # TODO: Is this ever executed?
        if asg_orig == "WarmPool" and asg_dest == "AutoScalingGroup":
            print("Handling instance moving from WarmPool to ASG")
        else:
            print("Controller is already saved. Not restoring")
            return

    controller_instanceobj = client.describe_instances(
        Filters=[{"Name": "instance-id", "Values": [asg_inst]}]
    )["Reservations"][0]["Instances"][0]

    # Assign EIP when new ASG instance is launched or handling switchover event
    eip = os.environ.get("EIP")
    if asg_dest == "AutoScalingGroup":
        if not assign_eip(client, controller_instanceobj, eip):
            raise AvxError("Could not assign EIP")

    api_private_access = os.environ.get("API_PRIVATE_ACCESS")
    new_private_ip = controller_instanceobj.get("NetworkInterfaces")[0].get(
        "PrivateIpAddress"
    )
    print(f"New Private IP {str(new_private_ip)}")

    if api_private_access == "True":
        controller_api_ip = new_private_ip
        print(
            "API Access to Controller will use Private IP : " + str(controller_api_ip)
        )
    else:
        if asg_dest == "WarmPool":
            controller_api_ip = controller_instanceobj["PublicIpAddress"]
        else:
            controller_api_ip = eip
    print("API Access to Controller will use IP : " + str(controller_api_ip))

    duplicate, sg_modified = temp_add_security_group_access(
        client, controller_instanceobj, api_private_access
    )
    if not duplicate:
        update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": sg_modified})
        print(f"created tmp access - updated CONTROLLER_TMP_SG_GRP: {os.environ.items()}")
    print(
        "0.0.0.0/0:443 rule is %s present %s"
        % (
            "already" if duplicate else "not",
            "" if duplicate else ". Modified Security group %s" % sg_modified,
        )
    )

    # This priv_ip belongs to older terminated instance
    priv_ip = os.environ.get("PRIV_IP")
    print(f"priv_ip = {priv_ip}")
    if (
        priv_ip
        and asg_dest == "AutoScalingGroup"
        and os.environ.get("INTER_REGION") != "True"
    ):
        s3_file = "CloudN_" + priv_ip + "_save_cloudx_config.enc"
        print(f"S3 backup file name is {s3_file}")

        if not is_backup_file_is_recent(s3_file):
            raise AvxError(
                f"HA event failed. Backup file does not exist or is older"
                f" than {MAXIMUM_BACKUP_AGE}"
            )

    try:
        if not duplicate:
            if os.environ.get("INTER_REGION") == "True":
                update_env_dict(
                    ecs_client, {"TMP_SG_GRP": sg_modified, "STATE": "INIT"}
                )
            else:
                update_env_dict(ecs_client, {"TMP_SG_GRP": sg_modified})

        total_time = 0

        while time.time() - start_time < HANDLE_HA_TIMEOUT:
            try:
                cid = login_to_controller(controller_api_ip, "admin", new_private_ip)
            except Exception as err:
                print(str(err))
                print("Login failed, trying again in " + str(WAIT_DELAY))
                total_time += WAIT_DELAY
                time.sleep(WAIT_DELAY)
            else:
                break

        if time.time() - start_time >= HANDLE_HA_TIMEOUT:
            print(
                "Could not login to the controller. Attempting to handle login failure"
            )
            handle_login_failure(
                controller_api_ip,
                client,
                ecs_client,
                controller_instanceobj,
                eip,
                cid,
            )
            return

        # When first deploying, priv_ip will be None
        if priv_ip and asg_orig == "EC2" and os.environ.get("INTER_REGION") != "True":
            version_file = "CloudN_" + priv_ip + "_save_cloudx_version.txt"
            print(f"Controller version file name is {version_file}")
            ctrl_version = retrieve_controller_version(
                version_file, controller_api_ip, cid
            )
        elif os.environ.get("CTRL_INIT_VER"):
            print(f'Controller version {os.environ.get("CTRL_INIT_VER")}')
            ctrl_version = os.environ.get("CTRL_INIT_VER")
        else:
            ctrl_version = "latest"

        # Set Customer ID
        set_customer_id(cid, controller_api_ip)

        # Initialize new Controller instance when asg_dest = ASG or WarmPool
        if asg_orig == "EC2":
            initial_setup_complete = run_initial_setup(
                controller_api_ip, cid, ctrl_version
            )
        else:
            initial_setup_complete = True  # No INIT needed for failover transition

        temp_acc_name = "tempacc"
        total_time = 0
        sleep = False
        created_temp_acc = False
        # created_prim_acc = False
        login_complete = False
        response_json = {}

        while time.time() - start_time < HANDLE_HA_TIMEOUT:
            print(
                "Maximum of "
                + str(int(HANDLE_HA_TIMEOUT - (time.time() - start_time)))
                + " seconds remaining"
            )

            if sleep:
                print(
                    "Waiting for safe initial setup completion, maximum of "
                    + str(INITIAL_SETUP_WAIT - total_time)
                    + " seconds remaining"
                )
                time.sleep(WAIT_DELAY)
            else:
                print(f"{INITIAL_SETUP_WAIT - total_time} seconds remaining")
                sleep = True

            if not login_complete:
                # Need to login again as initial setup invalidates cid after waiting
                print("Logging in again")
                try:
                    cid = login_to_controller(
                        controller_api_ip, "admin", new_private_ip
                    )
                except AvxError:  # It might not succeed since apache2 could restart
                    print("Cannot connect to the controller")
                    duplicate, sg_modified = temp_add_security_group_access(
                        client, controller_instanceobj, api_private_access
                    )
                    if not duplicate:
                        update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": sg_modified})
                        print(f"created tmp access - updated CONTROLLER_TMP_SG_GRP: {os.environ.items()}")
                    print(
                        "Default rule is %s present %s"
                        % (
                            "already" if duplicate else "not",
                            ""
                            if duplicate
                            else ". Modified Security group %s" % sg_modified,
                        )
                    )
                    sleep = False
                    time.sleep(INITIAL_SETUP_DELAY)
                    total_time += INITIAL_SETUP_DELAY
                    continue
                else:
                    login_complete = True

            if not initial_setup_complete:
                response_json = get_initial_setup_status(controller_api_ip, cid)
                print(f"Initial setup status {response_json}")

                if response_json.get("return", False) is True:
                    initial_setup_complete = True
                else:
                    print("Controller initialization failed")
                    return

            # Set admin email/password and create temp account
            if os.environ.get("INTER_REGION") == "True" or (
                initial_setup_complete
                and not priv_ip
                and asg_orig == "EC2"
                and asg_dest == "AutoScalingGroup"
            ):
                response_json = set_admin_email(
                    controller_api_ip, cid, os.environ.get("ADMIN_EMAIL")
                )
                if response_json.get("return", False) is not True:
                    print(
                        f"Unable to set admin email - {response_json.get('reason', '')}"
                    )

                response_json = set_admin_password(
                    controller_api_ip, cid, new_private_ip
                )
                if response_json.get("return", False) is not True:
                    print(
                        f"Unable to set admin password - {response_json.get('reason', '')}"
                    )

                response_json = create_cloud_account(
                    cid, controller_api_ip, os.environ.get("PRIMARY_ACC_NAME")
                )
                if response_json.get("return", False) is not True:
                    print(
                        f"Unable to set create cloud account - {response_json.get('reason', '')}"
                    )

                if response_json.get("return", False) is True:
                    if os.environ.get("INTER_REGION") == "True":
                        region = event["TopicArn"].split(":")[3]
                        # In the inter-region case, enable controller backups on
                        # the primary controller if INTER_REGION_BACKUP_ENABLED is true
                        if (
                            os.environ.get("INTER_REGION_BACKUP_ENABLED") == "True"
                            and os.environ.get("ACTIVE_REGION") == region
                            and priv_ip is None
                        ):
                            response_json = setup_ctrl_backup(
                                controller_api_ip,
                                cid,
                                os.environ.get("PRIMARY_ACC_NAME"),
                            )
                            print("Updating ECS configuration")
                            set_environ(
                                client,
                                ecs_client,
                                controller_instanceobj,
                                eip,
                            )
                            break
                        else:
                            print("Updating ECS configuration")
                            set_environ(
                                client,
                                ecs_client,
                                controller_instanceobj,
                                eip,
                            )
                            break
                    else:
                        response_json = setup_ctrl_backup(
                            controller_api_ip, cid, os.environ.get("PRIMARY_ACC_NAME")
                        )
                        print("Updating ECS configuration")
                        set_environ(client, ecs_client, controller_instanceobj, eip)
                        break
                else:
                    print(
                        f"Unable to create primary account {os.environ.get('PRIMARY_ACC_NAME')}"
                    )
                    break

            print(f"initial_setup_complete = {initial_setup_complete}")
            print(f"priv_ip= {priv_ip}")
            print(f"created_temp_acc = {created_temp_acc}")
            print(f"asg_dest = {asg_dest}")

            if asg_dest == "WarmPool":
                print("New WarmPool instance ready")
                return

            # Create temp account for DB restore
            if (
                initial_setup_complete
                and priv_ip
                and not created_temp_acc
                and asg_dest == "AutoScalingGroup"
            ):
                print("Creating temp account for DB restore")
                response_json = create_cloud_account(
                    cid, controller_api_ip, temp_acc_name
                )
                print(response_json)

                if response_json.get("return", False) is True:
                    created_temp_acc = True
                elif "already exists" in response_json.get("reason", ""):
                    created_temp_acc = True

                # Verify controller version
                version_file = "CloudN_" + priv_ip + "_save_cloudx_version.txt"
                s3_ctrl_version = retrieve_controller_version(version_file)
                print(f"Controller version fetched from S3: {s3_ctrl_version}")
                ctrl_ver = controller_version(controller_api_ip, cid)
                if s3_ctrl_version != ctrl_ver:
                    print(
                        f"Controller version fetched from S3 doesnt match with controller version: {ctrl_ver}"
                    )
                    print(f"Upgrading controller to {s3_ctrl_version}")
                    upgrade_controller(controller_api_ip, cid, s3_ctrl_version)
                    print("login to the controller again !!")
                    cid = login_to_controller(
                        controller_api_ip, "admin", new_private_ip
                    )

                # DB restore
                if os.environ.get("CUSTOMER_ID"):  # Support for migration to BYOL
                    set_customer_id(cid, controller_api_ip)
                response_json = restore_backup(
                    cid, controller_api_ip, s3_file, temp_acc_name
                )
                print(response_json)

                ## Create a new backup so that filename uses new_private_ip
                if response_json.get("return", False) is True:
                    print("Successfully restored backup")

                    # If restore succeeded, update private IP to that of the new instance now.
                    print("Creating new backup")
                    setup_ctrl_backup(controller_api_ip, cid, temp_acc_name, "true")

                    print("Updating ECS configuration")
                    set_environ(client, ecs_client, controller_instanceobj, eip)
                    return

                # Parsing response from restore_backup()
                if response_json.get("reason", "") == "account_password required.":
                    print("API is not ready yet, requires account_password")
                    total_time += WAIT_DELAY
                elif response_json.get("reason", "") == "valid action required":
                    print("API is not ready yet")
                    total_time += WAIT_DELAY
                elif (
                    response_json.get("reason", "") == "CID is invalid or expired."
                    or "Invalid session. Please login again."
                    in response_json.get("reason", "")
                    or f"Session {cid} not found" in response_json.get("reason", "")
                    or f"Session {cid} expired" in response_json.get("reason", "")
                ):
                    print("Service abrupty restarted")
                    sleep = False

                    try:
                        cid = login_to_controller(
                            controller_api_ip, "admin", new_private_ip
                        )
                    except AvxError:
                        pass
                elif response_json.get("reason", "") == "not run":
                    print("Initial setup not complete..waiting")
                    time.sleep(INITIAL_SETUP_DELAY)
                    total_time += INITIAL_SETUP_DELAY
                    sleep = False
                elif (
                    "Remote end closed connection without response"
                    in response_json.get("reason", "")
                ):
                    print("Remote side closed the connection..waiting")
                    time.sleep(INITIAL_SETUP_DELAY)
                    total_time += INITIAL_SETUP_DELAY
                    sleep = False
                elif "Failed to establish a new connection" in response_json.get(
                    "reason", ""
                ) or "Max retries exceeded with url" in response_json.get("reason", ""):
                    print("Failed to connect to the controller")
                    total_time += WAIT_DELAY
                else:
                    print(
                        "Restoring backup failed due to "
                        + str(response_json.get("reason", ""))
                    )
                    return

    finally:
        msg_json = json.loads(event["Message"])
        asg_client = boto3.client("autoscaling")
        response = asg_client.complete_lifecycle_action(
            AutoScalingGroupName=msg_json["AutoScalingGroupName"],
            LifecycleActionResult="CONTINUE",
            InstanceId=msg_json["EC2InstanceId"],
            LifecycleHookName=msg_json["LifecycleHookName"],
        )

        print(f"Complete lifecycle action response {response}")
        if not duplicate:
            print(f"Reverting sg {sg_modified}")
            task_def = ecs_client.describe_task_definition(
                taskDefinition=TASK_DEF_FAMILY,
            )
            print(f"handle_ctrl_ha_event.1 - task_def - {task_def}")
            env_vars = copy.deepcopy(
                task_def["taskDefinition"]["containerDefinitions"][0]["environment"]
            )
            env = {env_var["name"]: env_var["value"] for env_var in env_vars}
            sync_env_var(ecs_client, env, {"TMP_SG_GRP": ""})
            restored_access = restore_security_group_access(client, sg_modified, ecs_client)
            if restored_access:
                update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": ""})
        else:
            update_env_dict(ecs_client)
        print("- Completed function -")


def handle_cop_ha_event(client, ecs_client, event, asg_inst, asg_orig, asg_dest):
    # print the info
    print(f"environment: {os.environ.items()}")
    print("Waiting for copilot to update")
    time.sleep(600)
    try:
        # get current region copilot info
        current_region = os.environ.get("SQS_QUEUE_REGION", "")
        instance_name = os.environ.get("AVIATRIX_COP_TAG", "")
        curr_cop_eip = os.environ.get("COP_EIP", "")
        cop_deployment = os.environ.get("COP_DEPLOYMENT", "")
        copilot_init = os.environ.get("PRIV_IP", "") == ""
        if cop_deployment == "fault-tolerant":
            instance_name = f"{instance_name}-Main"

        # get current region copilot to restore eip
        curr_region_cop_instanceobj = aws_utils.get_ec2_instance(client, instance_name, "")
        if curr_region_cop_instanceobj == {}:
            raise AvxError(f"Unable to find copilot {instance_name}")
        print(f"curr_region_cop_instanceobj: {curr_region_cop_instanceobj}")
        print(f"single node assign IP: {time.strftime('%H:%M:%S', time.localtime())}")
        # Assign COP_EIP to current region copilot
        if json.loads(event["Message"]).get("Destination", "") == "AutoScalingGroup":
            if not assign_eip(client, curr_region_cop_instanceobj, curr_cop_eip):
                print(
                    f"Could not assign EIP '{curr_cop_eip}' to current region '{current_region}' Copilot: {curr_region_cop_instanceobj}"
                )
                raise AvxError("Could not assign EIP to primary region Copilot")

        cp_lib.handle_copilot_ha()
    except Exception as err:  # pylint: disable=broad-except
        print(str(traceback.format_exc()))
        print(f"handle_cop_ha_event failed with err: {str(err)}")
    finally:
        msg_json = json.loads(event["Message"])
        asg_client = boto3.client("autoscaling")
        try:
            response = asg_client.complete_lifecycle_action(
                AutoScalingGroupName=msg_json["AutoScalingGroupName"],
                LifecycleActionResult="CONTINUE",
                LifecycleActionToken=msg_json["LifecycleActionToken"],
                LifecycleHookName=msg_json["LifecycleHookName"],
            )
            print(f"Complete lifecycle action response {response}")
        except Exception as err:  # pylint: disable=broad-except
            print(f"Complete lifecycle action did not succeed. Lifecycle action may be completed already: {str(err)}")
        print("- Completed function -")
        return


def assign_eip(client, controller_instanceobj, eip):
    """Assign the EIP to the new instance"""

    cf_req = False
    try:
        if eip is None:
            cf_req = True
            eip = controller_instanceobj["NetworkInterfaces"][0]["Association"].get(
                "PublicIp"
            )
        eip_alloc_id = (
            client.describe_addresses(PublicIps=[eip])
            .get("Addresses")[0]
            .get("AllocationId")
        )
        client.associate_address(
            AllocationId=eip_alloc_id, InstanceId=controller_instanceobj["InstanceId"]
        )
    except Exception as err:
        if cf_req and "InvalidAddress.NotFound" in str(err):
            print(
                "EIP %s was not found. Please attach an EIP to the controller before enabling HA"
                % eip
            )
            return False
        print("Failed in assigning EIP %s" % str(err))
        return False
    else:
        print("Assigned/verified elastic IP")
        return True


def migrate_ip(
    controller_ip,
    CID="ABCD1234",
    previous_ip=None,
):
    base_url = "https://%s/v1/api" % controller_ip
    post_data = {
        "action": "migrate_controller_ip",
        "CID": CID,
        "previous_ip": previous_ip,
    }

    print("API endpoint url: %s", str(base_url))
    payload_with_hidden_password = dict(post_data)
    payload_with_hidden_password["CID"] = "************"
    print(
        f"Request payload: "
        f"{str(json.dumps(obj=payload_with_hidden_password, indent=4))}"
    )
    response = requests.post(base_url, data=post_data, verify=False)

    output = response.json()
    print(f"Aviatrix API response is: {output}")
    return output


def detach_autoscaling_target_group(region, env):
    as_client = boto3.client("autoscaling", region)
    try:
        resp = as_client.describe_load_balancer_target_groups(
            AutoScalingGroupName=env["CTRL_ASG"]
        )
        arn = resp["LoadBalancerTargetGroups"][0].get("LoadBalancerTargetGroupARN")
    except Exception as err:
        raise AvxError(f"Not able to fetch target group arn : {err}")

    if arn:
        try:
            detach_resp = as_client.detach_load_balancer_target_groups(
                AutoScalingGroupName=env["CTRL_ASG"],
                TargetGroupARNs=[
                    arn,
                ],
            )
            print(f"Successfully detached target group from asg in region {region}")
            return True
        except Exception as err:
            raise AvxError(
                f"Not able to detach target group from asg in region {region}: {err}"
            )


if __name__ == "__main__":
    main()
