""" Aviatrix Controller Deployment with HA Lambda script """
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
import copilot_main as cp_lib

# import version

urllib3.disable_warnings(InsecureRequestWarning)

HANDLE_HA_TIMEOUT = 840
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
    try:
        ecs_handler()
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

    try:
        region = event["TopicArn"].split(":")[3]
        print(f"Event in region {region}")
    except (AttributeError, IndexError, KeyError, TypeError) as e:
        pprint(queue_messages[0].body)
        print(e)
        return

    tmp_sg = os.environ.get("TMP_SG_GRP", "")
    asg = event.get("AutoScalingGroupName")
    # This code only needs to run when the SNS event is from the Controller ASG
    if (
        tmp_sg
        and os.environ.get("STATE", "") != "INIT"
        and asg == os.environ.get("CTRL_ASG")
    ):
        print("Lambda probably did not complete last time. Reverting sg %s" % tmp_sg)
        update_env_dict(ecs_client, {"TMP_SG_GRP": ""})
        restore_security_group_access(ec2_client, tmp_sg)

    try:
        sns_msg_json = json.loads(event["Message"])
        sns_alarm_name = sns_msg_json.get("AlarmName", "")
        sns_msg_asg = sns_msg_json.get("AutoScalingGroupName", "")
        sns_msg_lifecycle = sns_msg_json.get("LifecycleTransition", "")
        sns_msg_desc = sns_msg_json.get("Description", "")
        # https://docs.aws.amazon.com/autoscaling/ec2/userguide/warm-pools-eventbridge-events.html
        sns_msg_orig = sns_msg_json.get("Origin", "")
        sns_msg_dest = sns_msg_json.get("Destination", "")
        sns_msg_inst = sns_msg_json.get("EC2InstanceId", "")
        sns_msg_event = sns_msg_json.get("Event", "")
        sns_msg_trigger = sns_msg_json.get("Trigger", "")
        sns_msg_Nvalue = sns_msg_json.get("NewStateValue", "")
        sns_msg_Ovalue = sns_msg_json.get("OldStateValue", "")
        if sns_msg_trigger:
            MetricName = sns_msg_trigger["MetricName"]
        else:
            MetricName = ""
    except (KeyError, IndexError, ValueError) as err:
        raise AvxError("Could not parse SNS message %s" % str(err)) from err

    print(f"SNS Event {sns_msg_lifecycle} Description {sns_msg_desc}")

    # Moved INTER_REGION code up otherwise PRIV_IP will already be set.
    if sns_msg_event == "autoscaling:TEST_NOTIFICATION":
        print("Successfully received Test Event from ASG")
    # Use PRIV_IP to determine if this is the intial deployment. Don't handle INTER_REGION on initial deploy.
    elif (
        os.environ.get("INTER_REGION") == "True"
        and sns_msg_asg == os.environ.get("CTRL_ASG")
        and os.environ.get("PRIV_IP")
    ):
        pri_region = sns_region
        dr_region = os.environ.get("DR_REGION")
        handle_ctrl_inter_region_event(pri_region, dr_region)
    elif sns_msg_event == "autoscaling:EC2_INSTANCE_LAUNCHING_ERROR":
        print("Instance launch error, refer to logs for failure reason ")

    if sns_msg_lifecycle == "autoscaling:EC2_INSTANCE_LAUNCHING":
        if sns_msg_orig == "EC2" and sns_msg_dest == "AutoScalingGroup":
            print("New instance launched into AutoscalingGroup")
        elif sns_msg_orig == "EC2" and sns_msg_dest == "WarmPool":
            print("New instance launched into WarmPool")
        elif sns_msg_orig == "WarmPool" and sns_msg_dest == "AutoScalingGroup":
            print("Failover event..Instance moving from WarmPool into AutoScaling")
        else:
            print(
                f"Unknown instance launch origin {sns_msg_orig} and/or dest {sns_msg_dest}"
            )

        if sns_msg_asg == os.environ.get("CTRL_ASG"):
            handle_ctrl_ha_event(
                ec2_client,
                ecs_client,
                event,
                sns_msg_inst,
                sns_msg_orig,
                sns_msg_dest,
            )
        elif sns_msg_asg == os.environ.get("COP_ASG"):
            handle_cop_ha_event(
                ec2_client,
                ecs_client,
                event,
                sns_msg_inst,
                sns_msg_orig,
                sns_msg_dest,
            )


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
    """Update particular variables in the Environment variables in lambda"""

    env_dict = {
        "EIP": os.environ.get("EIP"),
        "COP_EIP": os.environ.get("COP_EIP"),
        "VPC_ID": os.environ.get("VPC_ID"),
        "AVIATRIX_TAG": os.environ.get("AVIATRIX_TAG"),
        "AVIATRIX_COP_TAG": os.environ.get("AVIATRIX_COP_TAG"),
        "CTRL_ASG": os.environ.get("CTRL_ASG"),
        "COP_ASG": os.environ.get("COP_ASG"),
        "API_PRIVATE_ACCESS": os.environ.get("API_PRIVATE_ACCESS", "False"),
        "PRIV_IP": os.environ.get("PRIV_IP", ""),
        "INST_ID": os.environ.get("INST_ID", ""),
        "S3_BUCKET_BACK": os.environ.get("S3_BUCKET_BACK"),
        "S3_BUCKET_REGION": os.environ.get("S3_BUCKET_REGION", ""),
        "DISKS": os.environ.get("DISKS", ""),
        "TAGS": os.environ.get("TAGS", "[]"),
        "TMP_SG_GRP": os.environ.get("TMP_SG_GRP", ""),
        "AWS_ROLE_APP_NAME": os.environ.get("AWS_ROLE_APP_NAME"),
        "AWS_ROLE_EC2_NAME": os.environ.get("AWS_ROLE_EC2_NAME"),
        "INTER_REGION": os.environ.get("INTER_REGION"),
        # 'AVIATRIX_USER_BACK': os.environ.get('AVIATRIX_USER_BACK'),
        # 'AVIATRIX_PASS_BACK': os.environ.get('AVIATRIX_PASS_BACK'),
    }
    if os.environ.get("INTER_REGION") == "True":
        env_dict["DR_REGION"] = os.environ.get("DR_REGION")
        env_dict["PRIMARY_ACC_NAME"] = os.environ.get("PRIMARY_ACC_NAME")
        # env_dict['CTRL_INIT_VER'] = os.environ.get('CTRL_INIT_VER')
        env_dict["CTRL_INIT_VER"] = os.environ.get("CTRL_INIT_VER", "")
        env_dict["ADMIN_EMAIL"] = os.environ.get("ADMIN_EMAIL")
        env_dict["PREEMPTIVE"] = os.environ.get("PREEMPTIVE", "")
        env_dict["ACTIVE_REGION"] = os.environ.get("ACTIVE_REGION")
        env_dict["STANDBY_REGION"] = os.environ.get("STANDBY_REGION")
        env_dict["ZONE_NAME"] = os.environ.get("ZONE_NAME")
        env_dict["RECORD_NAME"] = os.environ.get("RECORD_NAME")
        env_dict["INTER_REGION_BACKUP_ENABLED"] = os.environ.get(
            "INTER_REGION_BACKUP_ENABLED"
        )
    # wait_function_update_successful(lambda_client, context.function_name)
    env_dict.update(replace_dict)
    os.environ.update(replace_dict)
    print("Updating environment %s" % env_dict)
    current_task_def = ecs_client.describe_task_definition(
        taskDefinition=TASK_DEF_FAMILY,
    )

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

    env_def = new_task_def["containerDefinitions"][0]["environment"]
    for envvar in env_def:
        if envvar["name"] in env_dict:
            envvar["value"] = env_dict[envvar["name"]]
    print("Updating task definition")
    ecs_client.register_task_definition(**new_task_def)

    print("Updated environment dictionary")


def sync_env_var(ecs_client, env_dict, replace_dict={}):
    """Update DR environment variables in lambda"""
    # wait_function_update_successful(lambda_client, context.function_name)
    # Removing empty key's from the env
    empty_keys = [key for key, val in env_dict.items() if not val]
    for key in empty_keys:
        del env_dict[key]

    env_dict.update(replace_dict)

    print("Updating environment %s" % env_dict)
    current_task_def = ecs_client.describe_task_definition(
        taskDefinition=TASK_DEF_FAMILY,
    )
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

    env_def = new_task_def["containerDefinitions"][0]["environment"]
    for envvar in env_def:
        if envvar["name"] in env_dict:
            envvar["value"] = env_dict[envvar["name"]]
    print("Updating task definition")
    ecs_client.update_function_configuration(**new_task_def)
    print("Updated environment dictionary")


def wait_function_update_successful(lambda_client, function_name, raise_err=False):
    """Wait until get_function_configuration LastUpdateStatus=Successful"""
    # https://aws.amazon.com/blogs/compute/coming-soon-expansion-of-aws-lambda-states-to-all-functions/
    try:
        waiter = lambda_client.get_waiter("function_updated")
        print(f"Waiting for function update to be successful: {function_name}")
        waiter.wait(FunctionName=function_name)
        print(f"{function_name} update state is successful")
    except botocore.exceptions.WaiterError as err:
        print(str(err))
        if raise_err:
            raise AvxError(str(err)) from err


def login_to_controller(ip_addr, username, pwd):
    """Logs into the controller and returns the cid"""

    base_url = "https://" + ip_addr + "/v1/api"
    url = (
        base_url
        + "?action=login&username="
        + username
        + "&password="
        + urllib.parse.quote(pwd, "%")
    )
    try:
        response = requests.get(url, verify=False)
    except Exception as err:
        print(
            "Can't connect to controller with elastic IP %s. %s" % (ip_addr, str(err))
        )
        raise AvxError(str(err)) from err

    response_json = response.json()

    try:
        cid = response_json.pop("CID")
        print("Created new session with CID {}\n".format(mask(cid)))
    except KeyError as err:
        print(response_json)
        print("Unable to create session. {}".format(err))
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
    # mon_bool = controller_instanceobj.get('Monitoring', {}).get('State', 'disabled') != 'disabled'
    # monitoring = 'enabled' if mon_bool else 'disabled'

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

    env_dict = {
        "ADMIN_EMAIL": os.environ.get("ADMIN_EMAIL", ""),
        "PRIMARY_ACC_NAME": os.environ.get("PRIMARY_ACC_NAME", ""),
        "CTRL_INIT_VER": os.environ.get("CTRL_INIT_VER", ""),
        "EIP": eip,
        "COP_EIP": os.environ.get("COP_EIP"),
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
        "AWS_ROLE_APP_NAME": os.environ.get("AWS_ROLE_APP_NAME"),
        "AWS_ROLE_EC2_NAME": os.environ.get("AWS_ROLE_EC2_NAME"),
        "INTER_REGION": os.environ.get("INTER_REGION"),
        # 'AVIATRIX_USER_BACK': os.environ.get('AVIATRIX_USER_BACK'),
        # 'AVIATRIX_PASS_BACK': os.environ.get('AVIATRIX_PASS_BACK'),
    }
    if os.environ.get("INTER_REGION") == "True":
        env_dict["DR_REGION"] = os.environ.get("DR_REGION")
        env_dict["PREEMPTIVE"] = os.environ.get("PREEMPTIVE", "")
        env_dict["ACTIVE_REGION"] = os.environ.get("ACTIVE_REGION")
        env_dict["STANDBY_REGION"] = os.environ.get("STANDBY_REGION")
        env_dict["ZONE_NAME"] = os.environ.get("ZONE_NAME")
        env_dict["RECORD_NAME"] = os.environ.get("RECORD_NAME")
        env_dict["INTER_REGION_BACKUP_ENABLED"] = os.environ.get(
            "INTER_REGION_BACKUP_ENABLED"
        )
    print("Setting environment %s" % env_dict)
    current_task_def = ecs_client.describe_task_definition(
        taskDefinition=TASK_DEF_FAMILY,
    )

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

    env_def = new_task_def["containerDefinitions"][0]["environment"]
    for envvar in env_def:
        if envvar["name"] in env_dict:
            envvar["value"] = env_dict[envvar["name"]]
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

    # login_to_controller(eip, os.environ.get('AVIATRIX_USER_BACK'),
    #                     os.environ.get('AVIATRIX_PASS_BACK'))
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


def restore_security_group_access(client, sg_id):
    """Remove 0.0.0.0/0 rule in previously added security group"""

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
            "Previous lambda may have exceeded 5 min. Updating lambda config"
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
    aws_acc_num = client.get_caller_identity()["Account"]
    base_url = "https://%s/v1/api" % controller_ip
    post_data = {
        "action": "setup_account_profile",
        "account_name": account_name,
        "aws_account_number": aws_acc_num,
        "aws_role_arn": "arn:aws:iam::%s:role/%s"
        % (aws_acc_num, get_role("AWS_ROLE_APP_NAME", "aviatrix-role-app")),
        "aws_role_ec2": "arn:aws:iam::%s:role/%s"
        % (aws_acc_num, get_role("AWS_ROLE_EC2_NAME", "aviatrix-role-ec2")),
        "cloud_type": 1,
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

    restore_data = {
        "action": "restore_cloudx_config",
        "cloud_type": "1",
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


def set_customer_id(cid, controller_api_ip):
    """Set the customer ID if set in environment to migrate to a different AMI type"""

    print("Setting up Customer ID")
    base_url = "https://" + controller_api_ip + "/v1/api"
    post_data = {
        "CID": cid,
        "action": "setup_customer_id",
        "customer_id": os.environ.get("CUSTOMER_ID"),
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

    base_url = "https://%s/v1/api" % controller_ip

    post_data = {
        "action": "enable_cloudn_backup_config",
        "CID": cid,
        "cloud_type": "1",
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
        # print(output)

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


def get_ssm_creds(region):
    try:
        ssm_client = boto3.client("ssm", region)
        resp = ssm_client.get_parameters_by_path(
            Path="/aviatrix/controller/", WithDecryption=True
        )
        avx_params = {}
        for param in resp["Parameters"]:
            avx_params[param["Name"].split("/")[-1]] = param["Value"]
        return avx_params["password"]
    except Exception as err:
        raise AvxError(f"Error fetching creds from ssm")


def set_admin_password(controller_ip, cid, old_admin_password):
    """Set admin password"""

    # Fetch Aviatrix Controller credentials from encrypted SSM parameter store
    ssm_client = boto3.client("ssm", "us-east-1")
    resp = ssm_client.get_parameters_by_path(
        Path="/aviatrix/controller/", WithDecryption=True
    )

    avx_params = {}
    for param in resp["Parameters"]:
        avx_params[param["Name"].split("/")[-1]] = param["Value"]

    base_url = "https://%s/v1/api" % controller_ip

    post_data = {
        "action": "change_password",
        "CID": cid,
        "account_name": "admin",
        "user_name": "admin",
        "old_password": old_admin_password,
        "password": avx_params["password"],
    }

    payload_with_hidden_password = dict(post_data)
    payload_with_hidden_password["password"] = "************"
    payload_with_hidden_password["CID"] = "*********"
    # print("Request payload: \n" +
    #    str(json.dumps(obj=payload_with_hidden_password, indent=4)))

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


def handle_ctrl_inter_region_event(
    pri_region, dr_region, context, revert=False, preemptive=None
):
    start_time = time.time()
    # 1. Fetching all env variables in between regions
    pri_client = boto3.client("ec2", pri_region)
    pri_lambda_client = boto3.client("lambda", pri_region)
    dr_client = boto3.client("ec2", dr_region)
    dr_lambda_client = boto3.client("lambda", dr_region)
    function_name = context.function_name
    pri_env = pri_lambda_client.get_function_configuration(FunctionName=function_name)[
        "Environment"
    ]["Variables"]
    dr_env = dr_lambda_client.get_function_configuration(FunctionName=function_name)[
        "Environment"
    ]["Variables"]

    # if revert == True:
    #     if dr_env.get('STATE',"") == 'INIT':
    #         raise AvxError(f"{dr_region} is not fully initialized")
    #     elif pri_env.get('STATE',"") != 'ACTIVE':
    #         print("- Route 53 False Positive Alarm or DR is not active -")
    #         raise AvxError(f"{pri_region} is not Active")
    #     else:
    #         print("Initiating failback")

    # 2. Trying to find Instance in DR region
    if dr_env.get("INST_ID"):
        print(f"INST_ID: {dr_env.get('INST_ID')}")
        dr_instanceobj = dr_client.describe_instances(
            Filters=[
                {"Name": "instance-state-name", "Values": ["running"]},
                {"Name": "instance-id", "Values": [dr_env.get("INST_ID")]},
            ]
        )["Reservations"][0]["Instances"][0]
    elif dr_env.get("AVIATRIX_TAG"):
        print(f"AVIATRIX_TAG : {dr_env.get('AVIATRIX_TAG')}")
        dr_instanceobj = dr_client.describe_instances(
            Filters=[
                {"Name": "instance-state-name", "Values": ["running"]},
                {"Name": "tag:Name", "Values": [dr_env.get("AVIATRIX_TAG")]},
            ]
        )["Reservations"][0]["Instances"][0]
    else:
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
    print(
        "0.0.0.0/0:443 rule is %s present %s"
        % (
            "already" if dr_duplicate else "not",
            "" if dr_duplicate else ". Modified Security group %s" % dr_sg_modified,
        )
    )
    total_time = 0
    creds = get_ssm_creds("us-east-1")

    # Check if this is the Active or Standby region
    if pri_region == pri_env.get("ACTIVE_REGION"):
        print("This event happened in the active region:", pri_env.get("ACTIVE_REGION"))

        try:
            if not dr_duplicate:
                sync_env_var(
                    dr_lambda_client,
                    dr_env,
                    context,
                    {"TMP_SG_GRP": dr_sg_modified, "STATE": "INIT"},
                )
            else:
                sync_env_var(dr_lambda_client, dr_env, context, {"STATE": "INIT"})
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
            print("START: Migrate IP")
            migrate = migrate_ip(dr_api_ip, cid, pri_env["EIP"])
            print("END: Migrate IP")

            current_active_region = pri_env.get("ACTIVE_REGION")
            current_standby_region = pri_env.get("STANDBY_REGION")

            print(
                "Update ACTIVE_REGION & STANDBY_REGION in DR Lambda environment variables"
            )
            sync_env_var(
                dr_lambda_client,
                dr_env,
                context,
                {
                    "ACTIVE_REGION": current_standby_region,
                    "STANDBY_REGION": current_active_region,
                },
            )

            print(
                "Update ACTIVE_REGION & STANDBY_REGION in primary Lambda environment variables"
            )
            sync_env_var(
                pri_lambda_client,
                pri_env,
                context,
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

            # 6. Detach target group from asg if preemptive is False
            if migrate.get("return", False) is True and not revert:
                if pri_env["PREEMPTIVE"] == "False":
                    print("START: Detaching target group from ASG")
                    detach_autoscaling_target_group(pri_region, pri_env)
                    print("END: Detaching target group from ASG")

            # # 7. Terminate instance if revert is True
            # if revert == True:
            #     print(f"START: Stopping instance in {pri_region}")
            #     pri_client.stop_instances(InstanceIds=[pri_env['INST_ID']])
            #     print(f"END: Stopping instance in {pri_region}")

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
                restore_security_group_access(dr_client, dr_sg_modified)
            sync_env_var(
                dr_lambda_client,
                dr_env,
                context,
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
        # while total_time <= MAX_LOGIN_TIMEOUT:
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

        # if total_time >= MAX_LOGIN_TIMEOUT:
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

        # while total_time <= INITIAL_SETUP_WAIT:
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
                        region = event["Records"][0]["Sns"]["TopicArn"].split(":")[3]
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
                            print("Updating lambda configuration")
                            set_environ(
                                client,
                                ecs_client,
                                controller_instanceobj,
                                eip,
                            )
                            break
                        else:
                            print("Updating lambda configuration")
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
                        print("Updating lambda configuration")
                        set_environ(client, ecs_client, controller_instanceobj, eip)
                        break
                else:
                    print(
                        f"Unable to create primary account {os.environ.get('PRIMARY_ACC_NAME')}"
                    )
                    break

            # print(response_json)

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

                    print("Updating lambda configuration")
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
        # raise AvxError("Restore failed, did not update lambda config")
    finally:
        sns_msg_json = json.loads(event["Message"])
        asg_client = boto3.client("autoscaling")
        response = asg_client.complete_lifecycle_action(
            AutoScalingGroupName=sns_msg_json["AutoScalingGroupName"],
            LifecycleActionResult="CONTINUE",
            InstanceId=sns_msg_json["EC2InstanceId"],
            LifecycleHookName=sns_msg_json["LifecycleHookName"],
        )

        print(f"Complete lifecycle action response {response}")
        if not duplicate:
            print(f"Reverting sg {sg_modified}")
            task_def = ecs_client.describe_task_definition(
                taskDefinition=TASK_DEF_FAMILY,
            )
            env_vars = copy.deepcopy(task_def["containerDefinitions"][0]["environment"])
            env = {env_var["name"]: env_var["value"] for env_var in env_vars}
            sync_env_var(ecs_client, env, {"TMP_SG_GRP": ""})
            restore_security_group_access(client, sg_modified)
        else:
            update_env_dict(ecs_client)
        print("- Completed function -")


def handle_cop_ha_event(client, ecs_client, event, asg_inst, asg_orig, asg_dest):
    try:
        instance_name = os.environ.get("AVIATRIX_COP_TAG")
        print(f"Copilot instance name: {instance_name}")

        copilot_instanceobj = client.describe_instances(
            Filters=[
                {"Name": "instance-state-name", "Values": ["running"]},
                {"Name": "tag:Name", "Values": [instance_name]},
            ]
        )["Reservations"][0]["Instances"][0]

        print(f"{copilot_instanceobj}")

        # Assign COP_EIP
        if (
            json.loads(event["Records"][0]["Sns"]["Message"]).get("Destination", "")
            == "AutoScalingGroup"
        ):
            if not assign_eip(client, copilot_instanceobj, os.environ.get("COP_EIP")):
                raise AvxError("Could not assign EIP to Copilot")
        copilot_event = {
            "region": "",
            "copilot_init": True,
            "copilot_type": "",  # values should be "singleNode" or "clustered"
            "instance_ids": [
                "",
                "",
            ],  # list of instances that should be "instance_status_ok"
            "cluster_ha_main_node": True,  # if clustered copilot HA case, set to True if HA for main node
            "copilot_data_node_public_ips": ["", ""],  # cluster data nodes public IPs
            "copilot_data_node_private_ips": ["", ""],  # cluster data nodes private IPs
            "copilot_data_node_regions": [
                "",
                "",
            ],  # cluster data nodes regions (should be the same)
            "copilot_data_node_names": [
                "",
                "",
            ],  # names to be displayed in copilot cluster info
            "copilot_data_node_usernames": ["", ""],
            "copilot_data_node_passwords": ["", ""],
            "copilot_data_node_volumes": [
                "",
                "",
            ],  # linux volume names (eg "/dev/sdf") - can be the same
            "copilot_data_node_sg_names": [
                "",
                "",
            ],  # cluster data nodes security group names
            "controller_info": {
                "public_ip": "",
                "private_ip": "",
                "username": "",
                "password": "",
                "sg_id": "",  # controller security group ID
                "sg_name": "",  # controller security group name
            },
            "copilot_info": {
                "public_ip": "",
                "private_ip": "",
                "username": "",
                "password": "",
                "sg_id": "",  # (main) copilot security group ID
                "sg_name": "",  # (main) copilot security group name
            },
        }
        if False:
            cp_lib.handle_coplot_ha(event=copilot_event)

    except Exception as err:
        print(f"Can't find Copilot with name {instance_name}. {str(err)}")
    finally:
        sns_msg_json = json.loads(event["Message"])
        asg_client = boto3.client("autoscaling")
        response = asg_client.complete_lifecycle_action(
            AutoScalingGroupName=sns_msg_json["AutoScalingGroupName"],
            LifecycleActionResult="CONTINUE",
            LifecycleActionToken=sns_msg_json["LifecycleActionToken"],
            LifecycleHookName=sns_msg_json["LifecycleHookName"],
        )

        print(f"Complete lifecycle action response {response}")
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
