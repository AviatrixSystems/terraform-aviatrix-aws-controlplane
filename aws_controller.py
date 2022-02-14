""" Aviatrix Controller Deployment with HA Lambda script """

import time
import os
import uuid
import json
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
#import version

urllib3.disable_warnings(InsecureRequestWarning)

MAX_LOGIN_TIMEOUT = 800
WAIT_DELAY = 30

INITIAL_SETUP_WAIT = 180
INITIAL_SETUP_DELAY = 10

INITIAL_SETUP_API_WAIT = 20
#AMI_ID = 'https://aviatrix-download.s3-us-west-2.amazonaws.com/AMI_ID/ami_id.json'
MAXIMUM_BACKUP_AGE = 24 * 3600 * 3  # 3 days
AWS_US_EAST_REGION = 'us-east-1'

mask = lambda input: input[0:5] + '*' * 15 if isinstance(input, str) else ''

class AvxError(Exception):
    """ Error class for Aviatrix exceptions"""

print('Loading function')

def lambda_handler(event, context):
    """ Entry point of the lambda script"""
    try:
        _lambda_handler(event, context)
    except AvxError as err:
        print('Operation failed due to: ' + str(err))
    except Exception as err:  # pylint: disable=broad-except
        print(str(traceback.format_exc()))
        print("Lambda function failed due to " + str(err))


def _lambda_handler(event, context):
    """ Entry point of the lambda script without exception handling
        This lambda function will serve 2 kinds of requests:
        one time request from CFT - Request to setup HA (setup_ha method)
         made by Cloud formation template.
        sns_event - Request from sns to attach elastic ip to new instance
         created after controller failover. """

    sns_event = False
    print(f"Event: {event}")

    try:
        sns_event = event["Records"][0]["EventSource"] == "aws:sns"
        print("From SNS Event")
    except (AttributeError, IndexError, KeyError, TypeError):
        pass

    if os.environ.get("TESTPY") == "True":
        print("Testing")
        client = boto3.client(
            'ec2', region_name=os.environ["AWS_TEST_REGION"],
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_BACK"],
            aws_secret_access_key=os.environ["AWS_SECRET_KEY_BACK"])
        lambda_client = boto3.client(
            'lambda', region_name=os.environ["AWS_TEST_REGION"],
            aws_access_key_id=os.environ["AWS_ACCESS_KEY_BACK"],
            aws_secret_access_key=os.environ["AWS_SECRET_KEY_BACK"])
    else:
        client = boto3.client('ec2')
        lambda_client = boto3.client('lambda')

    tmp_sg = os.environ.get('TMP_SG_GRP', '')
    if tmp_sg:
        print("Lambda probably did not complete last time. Reverting sg %s" % tmp_sg)
        update_env_dict(lambda_client, context, {'TMP_SG_GRP': ''})
        restore_security_group_access(client, tmp_sg)

    if sns_event:
        try:
            sns_msg_json = json.loads(event["Records"][0]["Sns"]["Message"])
            sns_msg_asg = sns_msg_json.get('AutoScalingGroupName', "")
            sns_msg_event = sns_msg_json.get('LifecycleTransition', "")
            sns_msg_desc = sns_msg_json.get('Description', "")
            # https://docs.aws.amazon.com/autoscaling/ec2/userguide/warm-pools-eventbridge-events.html
            sns_msg_orig = sns_msg_json.get('Origin', "")
            sns_msg_dest = sns_msg_json.get('Destination', "")
            sns_msg_inst = sns_msg_json.get('EC2InstanceId', "")
        except (KeyError, IndexError, ValueError) as err:
            raise AvxError("Could not parse SNS message %s" % str(err)) from err

        print(f"SNS Event {sns_msg_event} Description {sns_msg_desc}")

        if sns_msg_event == "autoscaling:EC2_INSTANCE_LAUNCHING":
            if sns_msg_orig == "EC2" and sns_msg_dest == "AutoScalingGroup":
                print("New instance launched into AutoscalingGroup")
            elif sns_msg_orig == "EC2" and sns_msg_dest == "WarmPool":
                print("New instance launched into WarmPool")
            elif sns_msg_orig == "WarmPool" and sns_msg_dest == "AutoScalingGroup":
                print("HA event..Instance moving from WarmPool into AutoScaling")
            else:
                print(f"Unknown instance launch origin {sns_msg_orig} and/or dest {sns_msg_dest}")

            if sns_msg_asg == os.environ.get('CTRL_ASG'):
                handle_ctrl_ha_event(client, lambda_client, event, context, sns_msg_inst, sns_msg_orig, sns_msg_dest)
            elif sns_msg_asg == os.environ.get('COP_ASG'):
                handle_cop_ha_event (client, lambda_client, event, context, sns_msg_inst, sns_msg_orig, sns_msg_dest)

        elif sns_msg_event == "autoscaling:TEST_NOTIFICATION":
            print("Successfully received Test Event from ASG")
        elif sns_msg_event == "autoscaling:EC2_INSTANCE_LAUNCHING_ERROR":
            # and "The security group" in sns_msg_desc and "does not exist in VPC" in sns_msg_desc:
            # TODO: Change handling of LAUNC_ERROR. May not require below env variables?
            print("Instance launch error, recreating with new security group configuration")
            #sg_id = create_new_sg(client)
            #ami_id = os.environ.get('AMI_ID')
            #inst_type = os.environ.get('INST_TYPE')
            #key_name = os.environ.get('KEY_NAME')
    else:
        print("Unexpected source. Not from SNS")

# Why was HA not allowed on non-latest AMI?
# TODO: Not used anywhere now
def _check_ami_id(ami_id):
    """ Check if AMI is latest"""

    print("Verifying AMI ID")
    resp = requests.get(AMI_ID)
    ami_dict = json.loads(resp.content)
    for image_type in ami_dict:
        if ami_id in list(ami_dict[image_type].values()):
            print("AMI is valid")
            return True
    print("AMI is not latest. Cannot enable Controller HA. Please backup restore to the latest AMI"
          "before enabling controller HA")
    return False


def create_new_sg(client):
    """ Creates a new security group"""

    instance_name = os.environ.get('AVIATRIX_TAG')
    vpc_id = os.environ.get('VPC_ID')

    try:
        resp = client.create_security_group(Description='Aviatrix Controller',
                                            GroupName=instance_name,
                                            VpcId=vpc_id)
        sg_id = resp['GroupId']
    except (botocore.exceptions.ClientError, KeyError) as err:
        if "InvalidGroup.Duplicate" in str(err):
            rsp = client.describe_security_groups(GroupNames=[instance_name])
            sg_id = rsp['SecurityGroups'][0]['GroupId']
        else:
            raise AvxError(str(err)) from err

    try:
        client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {'IpProtocol': 'tcp',
                 'FromPort': 443,
                 'ToPort': 443,
                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp',
                 'FromPort': 80,
                 'ToPort': 80,
                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            ])
    except botocore.exceptions.ClientError as err:
        if "InvalidGroup.Duplicate" in str(err) or "InvalidPermission.Duplicate" in str(err):
            pass
        else:
            raise AvxError(str(err)) from err
    return sg_id


def update_env_dict(lambda_client, context, replace_dict):
    """ Update particular variables in the Environment variables in lambda"""

    env_dict = {
        'EIP': os.environ.get('EIP'),
        'COP_EIP': os.environ.get('COP_EIP'),
        'AMI_ID': os.environ.get('AMI_ID'),
        'VPC_ID': os.environ.get('VPC_ID'),
        'INST_TYPE': os.environ.get('INST_TYPE'),
        'KEY_NAME': os.environ.get('KEY_NAME'),
        'AVIATRIX_TAG': os.environ.get('AVIATRIX_TAG'),
        'AVIATRIX_COP_TAG': os.environ.get('AVIATRIX_COP_TAG'),
        'CTRL_ASG': os.environ.get('CTRL_ASG'),
        'COP_ASG': os.environ.get('COP_ASG'),
        'API_PRIVATE_ACCESS': os.environ.get('API_PRIVATE_ACCESS', "False"),
        'PRIV_IP': os.environ.get('PRIV_IP'),
        'INST_ID': os.environ.get('INST_ID'),
        'S3_BUCKET_BACK': os.environ.get('S3_BUCKET_BACK'),
        'S3_BUCKET_REGION': os.environ.get('S3_BUCKET_REGION', ''),
        'DISKS': os.environ.get('DISKS'),
        'TAGS': os.environ.get('TAGS', '[]'),
        'TMP_SG_GRP': os.environ.get('TMP_SG_GRP', ''),
        'AWS_ROLE_APP_NAME': os.environ.get('AWS_ROLE_APP_NAME'),
        'AWS_ROLE_EC2_NAME': os.environ.get('AWS_ROLE_EC2_NAME'),
        # 'AVIATRIX_USER_BACK': os.environ.get('AVIATRIX_USER_BACK'),
        # 'AVIATRIX_PASS_BACK': os.environ.get('AVIATRIX_PASS_BACK'),
    }
    env_dict.update(replace_dict)
    os.environ.update(replace_dict)

    lambda_client.update_function_configuration(FunctionName=context.function_name,
                                                Environment={'Variables': env_dict})
    print("Updated environment dictionary")


def login_to_controller(ip_addr, username, pwd):
    """ Logs into the controller and returns the cid"""

    base_url = "https://" + ip_addr + "/v1/api"
    url = base_url + "?action=login&username=" + username + "&password=" + \
          urllib.parse.quote(pwd, '%')
    try:
        response = requests.get(url, verify=False)
    except Exception as err:
        print("Can't connect to controller with elastic IP %s. %s" % (ip_addr,
                                                                      str(err)))
        raise AvxError(str(err)) from err

    response_json = response.json()

    try:
        cid = response_json.pop('CID')
        print("Created new session with CID {}\n".format(mask(cid)))
    except KeyError as err:
        print(response_json)
        print("Unable to create session. {}".format(err))
        raise AvxError("Unable to create session. {}".format(err)) from err
    print(response_json)
    return cid


def set_environ(client, lambda_client, controller_instanceobj, context,
                eip=None):
    """ Sets Environment variables """

    if eip is None:
        # From cloud formation. EIP is not known at this point. So get from controller inst
        eip = controller_instanceobj[
            'NetworkInterfaces'][0]['Association'].get('PublicIp')
    else:
        eip = os.environ.get('EIP')

    inst_id = controller_instanceobj['InstanceId']
    ami_id = controller_instanceobj['ImageId']
    vpc_id = controller_instanceobj['VpcId']
    inst_type = controller_instanceobj['InstanceType']
    keyname = controller_instanceobj.get('KeyName', '')
    priv_ip = controller_instanceobj.get('NetworkInterfaces')[0].get('PrivateIpAddress')
    iam_arn = controller_instanceobj.get('IamInstanceProfile', {}).get('Arn', '')
    #mon_bool = controller_instanceobj.get('Monitoring', {}).get('State', 'disabled') != 'disabled'
    #monitoring = 'enabled' if mon_bool else 'disabled'

    tags = controller_instanceobj.get("Tags", [])
    tags_stripped = []
    for tag in tags:
        key = tag.get("Key", "")
        # Tags starting with aws: is reserved
        if not key.startswith("aws:"):
            tags_stripped.append(tag)

    disks = []
    for volume in controller_instanceobj.get('BlockDeviceMappings', {}):
        ebs = volume.get('Ebs', {})
        if ebs.get('Status', 'detached') == 'attached':
            vol_id = ebs.get('VolumeId')
            vol = client.describe_volumes(VolumeIds=[vol_id])['Volumes'][0]
            disks.append({"VolumeId": vol_id,
                          "DeleteOnTermination": ebs.get('DeleteOnTermination'),
                          "VolumeType": vol["VolumeType"],
                          "Size": vol["Size"],
                          "Iops": vol.get("Iops", ""),
                          "Encrypted": vol["Encrypted"],
                          })

    env_dict = {
        'EIP': eip,
        'AMI_ID': ami_id,
        'VPC_ID': vpc_id,
        'INST_TYPE': inst_type,
        'KEY_NAME': keyname,
        'AVIATRIX_TAG': os.environ.get('AVIATRIX_TAG'),
        'API_PRIVATE_ACCESS': os.environ.get('API_PRIVATE_ACCESS', "False"),
        'PRIV_IP': priv_ip,
        'INST_ID': inst_id,
        'S3_BUCKET_BACK': os.environ.get('S3_BUCKET_BACK'),
        'S3_BUCKET_REGION': os.environ.get('S3_BUCKET_REGION', ''),
        'DISKS': json.dumps(disks),
        'TAGS': json.dumps(tags_stripped),
        'TMP_SG_GRP': os.environ.get('TMP_SG_GRP', ''),
        'AWS_ROLE_APP_NAME': os.environ.get('AWS_ROLE_APP_NAME'),
        'AWS_ROLE_EC2_NAME': os.environ.get('AWS_ROLE_EC2_NAME'),
        # 'AVIATRIX_USER_BACK': os.environ.get('AVIATRIX_USER_BACK'),
        # 'AVIATRIX_PASS_BACK': os.environ.get('AVIATRIX_PASS_BACK'),
    }
    print("Setting environment %s" % env_dict)

    lambda_client.update_function_configuration(FunctionName=context.function_name,
                                                Environment={'Variables': env_dict})
    os.environ.update(env_dict)


def verify_iam(controller_instanceobj):
    """ Verify IAM roles"""
    print("Verifying IAM roles ")
    iam_arn = controller_instanceobj.get('IamInstanceProfile', {}).get('Arn', '')
    if not iam_arn:
        return False
    return True


def verify_bucket(controller_instanceobj):
    """ Verify S3 and controller account credentials """
    print("Verifying bucket")
    try:
        s3_client = boto3.client('s3')
        resp = s3_client.get_bucket_location(Bucket=os.environ.get('S3_BUCKET_BACK'))
    except Exception as err:
        print("S3 bucket used for backup is not "
              "valid. %s" % str(err))
        return False, ""

    try:
        bucket_region = resp['LocationConstraint']

        # Buckets in Region us-east-1 have a LocationConstraint of null
        if bucket_region is None:
            print(f"Bucket region is None. Setting to {AWS_US_EAST_REGION}")
            bucket_region = AWS_US_EAST_REGION
    except KeyError:
        print("Key LocationConstraint not found in get_bucket_location response %s" % resp)
        return False, ""

    print("S3 bucket is valid.")
    eip = controller_instanceobj[
        'NetworkInterfaces'][0]['Association'].get('PublicIp')
    print(eip)

    # login_to_controller(eip, os.environ.get('AVIATRIX_USER_BACK'),
    #                     os.environ.get('AVIATRIX_PASS_BACK'))
    return True, bucket_region


def is_backup_file_is_recent(backup_file):
    """ Check if backup file is not older than MAXIMUM_BACKUP_AGE """

    try:
        s3c = boto3.client('s3', region_name=os.environ['S3_BUCKET_REGION'])
        try:
            file_obj = s3c.get_object(Key=backup_file, Bucket=os.environ.get('S3_BUCKET_BACK'))
        except botocore.exceptions.ClientError as err:
            print(str(err))
            return False

        age = time.time() - file_obj['LastModified'].timestamp()
        if age < MAXIMUM_BACKUP_AGE:
            print("Succesfully validated Backup file age")
            return True
        print(f"File age {age} is older than the maximum allowed value of {MAXIMUM_BACKUP_AGE}")
        return False
    except Exception as err:
        print(f"Checking backup file age failed due to {str(err)}")
        return False


def verify_backup_file(controller_instanceobj):
    """ Verify if s3 file exists"""
    print("Verifying Backup file")
    try:
        s3c = boto3.client('s3', region_name=os.environ['S3_BUCKET_REGION'])
        priv_ip = controller_instanceobj['NetworkInterfaces'][0]['PrivateIpAddress']
        version_file = "CloudN_" + priv_ip + "_save_cloudx_version.txt"

        retrieve_controller_version(version_file)
        s3_file = "CloudN_" + priv_ip + "_save_cloudx_config.enc"

        try:
            with open('/tmp/tmp.enc', 'wb') as data:
                s3c.download_fileobj(os.environ.get('S3_BUCKET_BACK'), s3_file, data)
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == "404":
                print("The object %s does not exist." % s3_file)
                return False, ""
            print(str(err))
            return False, ""
    except Exception as err:
        print("Verify Backup failed %s" % str(err))
        return False, ""
    else:
        return True, s3_file


def retrieve_controller_version(version_file):
    """ Get the controller version from backup file"""

    print("Retrieving version from file " + str(version_file))
    s3c = boto3.client('s3', region_name=os.environ['S3_BUCKET_REGION'])
    try:
        with open('/tmp/version_ctrlha.txt', 'wb') as data:
            s3c.download_fileobj(os.environ.get('S3_BUCKET_BACK'), version_file,
                                 data)
    except botocore.exceptions.ClientError as err:
        if err.response['Error']['Code'] == "404":
            print("The object does not exist.")
            raise AvxError("The cloudx version file does not exist") from err
        raise

    if not os.path.exists('/tmp/version_ctrlha.txt'):
        raise AvxError("Unable to open version file")

    with open("/tmp/version_ctrlha.txt") as fileh:
        buf = fileh.read()
    print("Retrieved version " + str(buf))

    if not buf:
        raise AvxError("Version file is empty")
    print("Parsing version")

    # TODO: Starting 6.5.2608(6.5c), ctrl_version should return buf[12:]
    try:
        ctrl_version = ".".join(((buf[12:]).split("."))[:-1])
    except (KeyboardInterrupt, IndexError, ValueError) as err:
        raise AvxError("Could not decode version") from err
    else:
        print("Parsed version sucessfully " + str(ctrl_version))
        return ctrl_version


def get_initial_setup_status(ip_addr, cid):
    """ Get status of the initial setup completion execution"""

    print("Checking initial setup")
    base_url = "https://" + ip_addr + "/v1/api"
    post_data = {"CID": cid,
                 "action": "initial_setup",
                 "subaction": "check"}

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        print(str(err))
        return {'return': False, 'reason': str(err)}
    return response.json()


def run_initial_setup(ip_addr, cid, ctrl_version):
    """ Boots the fresh controller to the specific version"""

    response_json = get_initial_setup_status(ip_addr, cid)
    if response_json.get('return') is True:
        print("Initial setup is already done. Skipping")
        return True

    post_data = {"target_version": ctrl_version,
                 "action": "initial_setup",
                 "subaction": "run"}
    print("Trying to run initial setup %s\n" % str(post_data))
    post_data["CID"] = cid
    base_url = "https://" + ip_addr + "/v1/api"

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print("Server closed the connection while executing initial setup API."
                  " Ignoring response")
            response_json = {'return': True, 'reason': 'Warning!! Server closed the connection'}
        else:
            raise AvxError("Failed to execute initial setup: " + str(err)) from err
    else:
        response_json = response.json()
        # Controllers running 6.4 and above would be unresponsive after initial_setup

    print(response_json)

    time.sleep(INITIAL_SETUP_API_WAIT)

    if response_json.get('return') is True:
        print("Successfully initialized the controller")
    else:
        raise AvxError("Could not bring up the new controller to the "
                       "specific version")
    return False


def temp_add_security_group_access(client, controller_instanceobj, api_private_access):
    """ Temporarily add 0.0.0.0/0 rule in one security group"""

    sgs = [sg_['GroupId'] for sg_ in controller_instanceobj['SecurityGroups']]
    if api_private_access == "True":
        return True, sgs[0]

    if not sgs:
        raise AvxError("No security groups were attached to controller")

    try:
        client.authorize_security_group_ingress(
            GroupId=sgs[0],
            IpPermissions=[{'IpProtocol': 'tcp',
                            'FromPort': 443,
                            'ToPort': 443,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                           ])
    except botocore.exceptions.ClientError as err:
        if "InvalidPermission.Duplicate" in str(err):
            return True, sgs[0]

        print(str(err))
        raise

    return False, sgs[0]


def restore_security_group_access(client, sg_id):
    """ Remove 0.0.0.0/0 rule in previously added security group"""

    try:
        client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{'IpProtocol': 'tcp',
                            'FromPort': 443,
                            'ToPort': 443,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                           ])
    except botocore.exceptions.ClientError as err:
        if "InvalidPermission.NotFound" not in str(err) and "InvalidGroup" not in str(err):
            print(str(err))


def handle_login_failure(priv_ip,client, lambda_client,
                        controller_instanceobj, context,eip):
    """ Handle login failure through private IP"""

    print("Checking for backup file")
    new_version_file = "CloudN_" + priv_ip + "_save_cloudx_version.txt"

    try:
        retrieve_controller_version(new_version_file)
    except Exception as err:
        print(str(err))
        # TODO: Infinite loop if unable to login to first instance?
        print("Could not retrieve new version file. Stopping instance. ASG will terminate and "
              "launch a new instance")
        inst_id = controller_instanceobj['InstanceId']
        print("Stopping %s" % inst_id)
        client.stop_instances(InstanceIds=[inst_id])
    else:
        print("Successfully retrieved version. Previous restore operation had succeeded. "
              "Previous lambda may have exceeded 5 min. Updating lambda config")
        set_environ(client, lambda_client, controller_instanceobj, context, eip)


def get_role(role, default):
    name = os.environ.get(role)
    if len(name) == 0 :
        return default
    return name

def create_cloud_account(cid, controller_ip, account_name):
    """ Create a temporary account to restore the backup"""

    print("Creating temporary account")
    client = boto3.client('sts')
    aws_acc_num = client.get_caller_identity()["Account"]
    base_url = "https://%s/v1/api" % controller_ip
    post_data = {"action": "setup_account_profile",
                 "account_name": account_name,
                 "aws_account_number": aws_acc_num,
                 "aws_role_arn": "arn:aws:iam::%s:role/%s" % (aws_acc_num, get_role("AWS_ROLE_APP_NAME", "aviatrix-role-app")),
                 "aws_role_ec2": "arn:aws:iam::%s:role/%s" % (aws_acc_num, get_role("AWS_ROLE_EC2_NAME", "aviatrix-role-ec2")),
                 "cloud_type": 1,
                 "aws_iam": "true"}

    print("Trying to create account with data %s\n" % str(post_data))
    post_data["CID"] = cid

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print("Server closed the connection while executing create account API."
                  " Ignoring response")
            output = {"return": True, 'reason': 'Warning!! Server closed the connection'}
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()

    return output


def restore_backup(cid, controller_ip, s3_file, account_name):
    """ Restore backup from the s3 bucket"""

    restore_data = {
        "action": "restore_cloudx_config",
        "cloud_type": "1",
        "account_name": account_name,
        "file_name": s3_file,
        "bucket_name": os.environ.get('S3_BUCKET_BACK')}

    print("Trying to restore config with data %s\n" % str(restore_data))
    restore_data["CID"] = cid
    base_url = "https://" + controller_ip + "/v1/api"

    try:
        response = requests.post(base_url, data=restore_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print("Server closed the connection while executing restore_cloudx_config API."
                  " Ignoring response")
            response_json = {"return": True, 'reason': 'Warning!! Server closed the connection'}
        else:
            print(str(err))
            response_json = {"return": False, "reason": str(err)}
    else:
        response_json = response.json()

    return response_json


def set_customer_id(cid, controller_api_ip):
    """ Set the customer ID if set in environment to migrate to a different AMI type"""

    print("Setting up Customer ID")
    base_url = "https://" + controller_api_ip + "/v1/api"
    post_data = {"CID": cid,
                 "action": "setup_customer_id",
                 "customer_id": os.environ.get("CUSTOMER_ID")}

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print("Server closed the connection while executing setup_customer_id API."
                  " Ignoring response")
            response_json = {"return": True, 'reason': 'Warning!! Server closed the connection'}
            time.sleep(WAIT_DELAY)
        else:
            response_json = {"return": False, "reason": str(err)}
    else:
        response_json = response.json()

    if response_json.get('return') is True:
        print("Customer ID successfully programmed")
    else:
        print("Customer ID programming failed. DB restore will fail: " +
              response_json.get('reason', ""))


def setup_ctrl_backup(controller_ip,cid,acc_name,now=None):
    """ Enable S3 backup """

    base_url = "https://%s/v1/api" % controller_ip

    post_data = {"action": "enable_cloudn_backup_config",
                 "CID": cid,
                 "cloud_type":"1",
                 "account_name":acc_name,
                 "bucket_name":os.environ.get('S3_BUCKET_BACK'),
                 "multiple":"true",
                 "region":"us-east-1",
                 "now":now
                 }

    print("Creating S3 backup: " + str(json.dumps(obj=post_data)))

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print("Server closed the connection while executing create account API."
                  " Ignoring response")
            output = {"return": True, 'reason': 'Warning!! Server closed the connection'}
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()
        print(output)

    return output

def set_admin_email(controller_ip,cid,admin_email):
    """ "add_admin_email_addr" API is supported by all controller versions since 2.6 """

    base_url = "https://%s/v1/api" % controller_ip
    post_data = {"action": "add_admin_email_addr",
                 "CID": cid,
                 "admin_email": admin_email}

    print("Creating admin account: " + str(json.dumps(obj=post_data)))

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print("Server closed the connection while executing create account API."
                  " Ignoring response")
            output = {"return": True, 'reason': 'Warning!! Server closed the connection'}
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()

    return output


def set_admin_password(controller_ip,cid,old_admin_password):
    """ Set admin password """

    # Fetch Aviatrix Controller credentials from encrypted SSM parameter store
    ssm_client = boto3.client('ssm')
    resp = ssm_client.get_parameters_by_path(Path="/aviatrix/controller/",WithDecryption=True)

    avx_params = {}
    for param in resp['Parameters']:
        avx_params[param['Name'].split("/")[-1]] = param['Value']

    base_url = "https://%s/v1/api" % controller_ip

    post_data = {
        "action": "change_password",
        "CID": cid,
        "account_name": "admin",
        "user_name": "admin",
        "old_password": old_admin_password,
        "password": avx_params['password']
    }

    payload_with_hidden_password = dict(post_data)
    payload_with_hidden_password["password"] = "************"
    print("Request payload: \n" +
        str(json.dumps(obj=payload_with_hidden_password, indent=4)))

    try:
        response = requests.post(base_url, data=post_data, verify=False)
    except requests.exceptions.ConnectionError as err:
        if "Remote end closed connection without response" in str(err):
            print("Server closed the connection while executing create account API."
                  " Ignoring response")
            output = {"return": True, 'reason': 'Warning!! Server closed the connection'}
            time.sleep(INITIAL_SETUP_DELAY)
        else:
            output = {"return": False, "reason": str(err)}
    else:
        output = response.json()

    return output



def handle_ctrl_ha_event(client, lambda_client, event, context, asg_inst, asg_orig, asg_dest):

    """ Restores the backup by doing the following
    1. Login to new controller
    2. There are 3 cases depending on asg_orig and asg_dest:
        a) asg_orig = EC2 and asg_dest = AutoScalingGroup
            i) Assign the EIP to the new Controller
            ii) Run initial setup and boot to latest version
            iii) Set admin email and password
            iv) Create primary AWS account
            v) Setup S3 backup
        b) asg_orig = EC2 and asg_dest = WarmPool
            i) Update Name tag to indicate standby Controller
            ii) Run initial setup and boot to specific version parsed from backup
        c) asg_orig = WarmPool and asg_dest = AutoScalingGroup
            i) Update Name tag to indicate standby instance is now active
            ii) Assign the EIP to the new Controller
            iii) Login and create temp AWS account
            ii) Restore configuration from backup """

    # asg_orig  and asg_dest are among (EC2, WarmPool, AutoScalingGroup)
    print(f"ASG event from origin {asg_orig} to destination {asg_dest}")
    if asg_orig == "EC2" and asg_dest == "WarmPool":
        warm_inst = True
        client.create_tags(Resources=[asg_inst],Tags=[{'Key':'Name','Value':os.environ.get('AVIATRIX_TAG')+'(Standby)'}])

    if asg_orig == "WarmPool" and asg_dest == "AutoScalingGroup":
        client.create_tags(Resources=[asg_inst],Tags=[{'Key':'Name','Value':os.environ.get('AVIATRIX_TAG')}])

    old_inst_id = os.environ.get('INST_ID')
    print(f"Old instance ID = {old_inst_id}")
    if old_inst_id == asg_inst:
        if asg_orig == "WarmPool" and asg_dest == "AutoScalingGroup":
            print("Handling instance moving from WarmPool to ASG")
        else:
            print("Controller is already saved. Not restoring")
            return

    controller_instanceobj = client.describe_instances(
            Filters=[{'Name': 'instance-id', 'Values': [asg_inst]}]
                    )['Reservations'][0]['Instances'][0]

    # Assign EIP when new ASG instance is launched or handling switchover event
    if asg_dest == "AutoScalingGroup":
        if not assign_eip(client, controller_instanceobj, os.environ.get('EIP')):
            raise AvxError("Could not assign EIP")

    eip = os.environ.get('EIP')
    api_private_access = os.environ.get('API_PRIVATE_ACCESS')
    new_private_ip = controller_instanceobj.get(
        'NetworkInterfaces')[0].get('PrivateIpAddress')
    print("New Private IP " + str(new_private_ip))

    if api_private_access == "True":
        controller_api_ip = new_private_ip
        print("API Access to Controller will use Private IP : " + str(controller_api_ip))
    else:
        if asg_dest == "WarmPool":
            controller_api_ip = controller_instanceobj['PublicIpAddress']
        else:
            controller_api_ip = eip
    print("API Access to Controller will use Public IP : " + str(controller_api_ip))

    duplicate, sg_modified = temp_add_security_group_access(client, controller_instanceobj,
                                                            api_private_access)
    print("0.0.0.0:443/0 rule is %s present %s" %
          ("already" if duplicate else "not",
           "" if duplicate else ". Modified Security group %s" % sg_modified))

    # This priv_ip belongs to older terminated instance
    # When first deploying, priv_ip will be None
    priv_ip = os.environ.get('PRIV_IP')
    if priv_ip and asg_orig == "WarmPool" and asg_dest == "AutoScalingGroup":
        s3_file = "CloudN_" + priv_ip + "_save_cloudx_config.enc"
        print(f"S3 backup file name is {s3_file}")

        if not is_backup_file_is_recent(s3_file):
            raise AvxError(f"HA event failed. Backup file does not exist or is older"
                       f" than {MAXIMUM_BACKUP_AGE}")

    try:
        if not duplicate:
            update_env_dict(lambda_client, context, {'TMP_SG_GRP': sg_modified})

        total_time = 0
        while total_time <= MAX_LOGIN_TIMEOUT:
            try:
                cid = login_to_controller(controller_api_ip, "admin", new_private_ip)
            except Exception as err:
                print(str(err))
                print("Login failed, trying again in " + str(WAIT_DELAY))
                total_time += WAIT_DELAY
                time.sleep(WAIT_DELAY)
            else:
                break

        if total_time >= MAX_LOGIN_TIMEOUT:
            print("Could not login to the controller. Attempting to handle login failure")
            handle_login_failure(controller_api_ip, client, lambda_client, controller_instanceobj,
                                 context, eip)
            return

        # When first deploying, priv_ip will be None
        if priv_ip and asg_orig == "EC2":
            version_file = "CloudN_" + priv_ip + "_save_cloudx_version.txt"
            print(f"Controller version file name is {version_file}")
            ctrl_version = retrieve_controller_version(version_file)
        else:
            ctrl_version = "latest"

        # Initialize new Controller instance
        # Skip init when asg_orig = WarmPool and asg_dest = ASG
        if asg_orig == "EC2":
            initial_setup_complete = run_initial_setup(controller_api_ip, cid, ctrl_version)
        else:
            initial_setup_complete = True

        temp_acc_name = "tempacc"
        total_time = 0
        sleep = False
        created_temp_acc = False
        created_prim_acc = False
        login_complete = False
        response_json = {}

        while total_time <= INITIAL_SETUP_WAIT:
            if sleep:
                print("Waiting for safe initial setup completion, maximum of " +
                      str(INITIAL_SETUP_WAIT - total_time) + " seconds remaining")
                time.sleep(WAIT_DELAY)
            else:
                print(f"{INITIAL_SETUP_WAIT - total_time} seconds remaining")
                sleep = True

            if not login_complete:
                # Need to login again as initial setup invalidates cid after waiting
                print("Logging in again")
                try:
                    cid = login_to_controller(controller_api_ip, "admin", new_private_ip)
                except AvxError:  # It might not succeed since apache2 could restart
                    print("Cannot connect to the controller")
                    sleep = False
                    time.sleep(INITIAL_SETUP_DELAY)
                    total_time += INITIAL_SETUP_DELAY
                    continue
                else:
                    login_complete = True

            if not initial_setup_complete:
                response_json = get_initial_setup_status(controller_api_ip, cid)
                print("Initial setup status %s" % response_json)
                if response_json.get('return', False) is True:
                    initial_setup_complete = True
                #else:
                    # TODO: Does it make sense to re-attempt init?

            # Should this be done before initialization?
            if initial_setup_complete and not priv_ip and asg_orig == "EC2" and asg_dest == "AutoScalingGroup":
                response_json = set_admin_email(controller_api_ip,cid,os.environ.get("ADMIN_EMAIL"))
                if response_json.get('return', False) is not True:
                    print(f"Unable to set admin email - {response_json.get('reason', '')}")
                response_json = set_admin_password(controller_api_ip,cid,new_private_ip)
                if response_json.get('return', False) is not True:
                    print(f"Unable to set admin password - {response_json.get('reason', '')}")
                response_json = create_cloud_account(cid, controller_api_ip, os.environ.get("PRIMARY_ACC_NAME"))
                if response_json.get('return', False) is not True:
                    print(f"Unable to set create cloud account - {response_json.get('reason', '')}")

                if response_json.get('return', False) is True:
                    created_prim_acc = True
                elif "already exists" in response_json.get('reason', ''):
                    created_prim_acc = True

                response_json = setup_ctrl_backup(controller_api_ip,cid,os.environ.get("PRIMARY_ACC_NAME"))
                print(response_json)

            # Create temp account for DB restore
            if initial_setup_complete and priv_ip and not created_temp_acc and asg_orig == "WarmPool" and asg_dest == "AutoScalingGroup":
                response_json = create_cloud_account(cid, controller_api_ip, temp_acc_name)
                print(response_json)
                if response_json.get('return', False) is True:
                    created_temp_acc = True
                elif "already exists" in response_json.get('reason', ''):
                    created_temp_acc = True

            # DB restore
            if created_temp_acc and initial_setup_complete and asg_orig == "WarmPool" and asg_dest == "AutoScalingGroup":
                if os.environ.get("CUSTOMER_ID"):  # Support for license migration scenario
                    set_customer_id(cid, controller_api_ip)
                response_json = restore_backup(cid, controller_api_ip, s3_file, temp_acc_name)
                print(response_json)
                # Create a new backup so that filename uses new_private_ip
                response_json = setup_ctrl_backup(controller_api_ip,cid,temp_acc_name,'true')
            else: # When first deploying, need to run set_environ()
                response_json['return'] = True
                created_temp_acc = True

            # If restore succeeded, update private IP to that of the new instance now.
            # During fresh install, they will be None. No backup restore on first run
            if response_json.get('return', False) is True and created_temp_acc:
                print("Successfully restored backup. Updating lambda configuration")
                if asg_dest == "AutoScalingGroup":
                    set_environ(client, lambda_client, controller_instanceobj, context, eip)
                    print("Updated lambda configuration")
                print("Controller HA event has been successfully handled")
                return

            # Parsing response from restore_backup()
            if response_json.get('reason', '') == 'account_password required.':
                print("API is not ready yet, requires account_password")
                total_time += WAIT_DELAY
            elif response_json.get('reason', '') == 'valid action required':
                print("API is not ready yet")
                total_time += WAIT_DELAY
            elif response_json.get('reason', '') == 'CID is invalid or expired.' or \
                    "Invalid session. Please login again." in response_json.get('reason', '') or \
                    f"Session {cid} not found" in response_json.get('reason', '') or \
                    f"Session {cid} expired" in response_json.get('reason', ''):
                print("Service abrupty restarted")
                sleep = False

                try:
                    cid = login_to_controller(controller_api_ip, "admin", new_private_ip)
                except AvxError:
                    pass
            elif response_json.get('reason', '') == 'not run':
                print('Initial setup not complete..waiting')
                time.sleep(INITIAL_SETUP_DELAY)
                total_time += INITIAL_SETUP_DELAY
                sleep = False
            elif 'Remote end closed connection without response' in response_json.get('reason', ''):
                print('Remote side closed the connection..waiting')
                time.sleep(INITIAL_SETUP_DELAY)
                total_time += INITIAL_SETUP_DELAY
                sleep = False
            elif "Failed to establish a new connection" in response_json.get('reason', '') \
                    or "Max retries exceeded with url" in response_json.get('reason', ''):
                print('Failed to connect to the controller')
                total_time += WAIT_DELAY
            else:
                print("Restoring backup failed due to " +
                      str(response_json.get('reason', '')))
                return
        raise AvxError("Restore failed, did not update lambda config")
    finally:
        sns_msg_json = json.loads(event["Records"][0]["Sns"]["Message"])
        asg_client = boto3.client('autoscaling')
        response = asg_client.complete_lifecycle_action(
                        AutoScalingGroupName=sns_msg_json['AutoScalingGroupName'],
                        LifecycleActionResult='CONTINUE',
                        LifecycleActionToken=sns_msg_json['LifecycleActionToken'],
                        LifecycleHookName=sns_msg_json['LifecycleHookName'])

        print(f"Complete lifecycle action response {response}")
        if not duplicate:
            print(f"Reverting sg {sg_modified}")
            if asg_orig == "EC2" and asg_dest == "AutoScalingGroup":
                update_env_dict(lambda_client, context, {'TMP_SG_GRP': ''})
            restore_security_group_access(client, sg_modified)


def handle_cop_ha_event (client, lambda_client, event, context, asg_inst, asg_orig, asg_dest):
    try:
        instance_name = os.environ.get('AVIATRIX_COP_TAG')
        print(f"Copilot instance name: {instance_name}")

        copilot_instanceobj = client.describe_instances(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']},
                {'Name': 'tag:Name', 'Values': [instance_name]}]
                )['Reservations'][0]['Instances'][0]

        print(f"{copilot_instanceobj}")

        # Assign COP_EIP
        if json.loads(event["Records"][0]["Sns"]["Message"]).get('Destination', "") == "AutoScalingGroup":
            if not assign_eip(client, copilot_instanceobj, os.environ.get('COP_EIP')):
                raise AvxError("Could not assign EIP to Copilot")
    except Exception as err:
        print(f"Can't find Copilot with name {instance_name}. {str(err)}")
    finally:
        sns_msg_json = json.loads(event["Records"][0]["Sns"]["Message"])
        asg_client = boto3.client('autoscaling')
        response = asg_client.complete_lifecycle_action(
                        AutoScalingGroupName=sns_msg_json['AutoScalingGroupName'],
                        LifecycleActionResult='CONTINUE',
                        LifecycleActionToken=sns_msg_json['LifecycleActionToken'],
                        LifecycleHookName=sns_msg_json['LifecycleHookName'])

        print(f"Complete lifecycle action response {response}")
        return


def assign_eip(client, controller_instanceobj, eip):
    """ Assign the EIP to the new instance"""

    cf_req = False
    try:
        if eip is None:
            cf_req = True
            eip = controller_instanceobj['NetworkInterfaces'][0]['Association'].get('PublicIp')
        eip_alloc_id = client.describe_addresses(
            PublicIps=[eip]).get('Addresses')[0].get('AllocationId')
        client.associate_address(AllocationId=eip_alloc_id,
                                 InstanceId=controller_instanceobj['InstanceId'])
    except Exception as err:
        if cf_req and "InvalidAddress.NotFound" in str(err):
            print("EIP %s was not found. Please attach an EIP to the controller before enabling HA"
                  % eip)
            return False
        print("Failed in assigning EIP %s" % str(err))
        return False
    else:
        print("Assigned/verified elastic IP")
        return True


def validate_keypair(key_name):
    """ Validates Keypairs"""
    try:
        client = boto3.client('ec2')
        response = client.describe_key_pairs()
    except botocore.exceptions.ClientError as err:
        raise AvxError(str(err)) from err

    key_aws_list = [key['KeyName'] for key in response['KeyPairs']]
    if key_name not in key_aws_list:
        print("Key does not exist. Creating")
        try:
            client = boto3.client('ec2')
            client.create_key_pair(KeyName=key_name)
        except botocore.exceptions.ClientError as err:
            raise AvxError(str(err)) from err
    else:
        print("Key exists")
