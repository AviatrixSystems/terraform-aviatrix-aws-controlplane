import boto3
import json
import os
import socket
import sys
import time
import traceback
import urllib3

# from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
from pip._vendor import requests
from pprint import pprint


# urllib3.disable_warnings(InsecureRequestWarning)


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
    peer_region = os.environ.get("peer_region")
    sns_topic_arn = os.environ.get("sns_topic_arn")

    ecs_cluster = os.environ.get("ecs_cluster")
    ecs_task_def = os.environ.get("ecs_task_def")
    subnets = [os.environ.get("ecs_subnet_1"), os.environ.get("ecs_subnet_2")]
    security_groups = [os.environ.get("ecs_security_group")]

    # print("Triggering ECS")
    # run_ecs_task(ecs_cluster, ecs_task_def, subnets, security_groups, "ENABLED", region)

    TASK_DEF_FAMILY = "AVX_PLATFORM_HA"

    ip = os.environ.get("peer_priv_ip")

    # Get the peer private IP if not set
    if os.environ.get("peer_priv_ip") == "":
        print("peer_priv_ip not set, retrieving from peer region")
        ip = get_priv_ip(peer_region, TASK_DEF_FAMILY)
        print("Setting peer_priv_ip to", ip)
        response = update_lamba_env_vars(
            "aviatrix_healthcheck", region, "peer_priv_ip", ip
        )
        print(response)

    # env_vars = get_task_def_env_vars(peer_region, TASK_DEF_FAMILY)
    # print("env_vars:", env_vars)

    # state = env_vars.get("STATE", "NotSpecified")

    # ssm_path = env_vars.get("AVX_PASSWORD_SSM_PATH")
    # ssm_region = env_vars.get("AVX_PASSWORD_SSM_REGION")

    # if env_vars.get("AVX_PASSWORD") == "":
    #     password = get_ssm_parameter_value(ssm_path, ssm_region)
    # else:
    #     password = env_vars.get("AVX_PASSWORD")

    # print("state:", state)
    # print("ssm_path:", ssm_path)
    # print("ssm_region:", ssm_region)
    # print("password:", password)

    # print("ip:", ip)
    # cid = login_to_controller(ip, "admin", password)
    # print("login_to_controller:", cid)
    # print("is_controller_ready", is_controller_ready_v2(ip, cid))

    print(f"The private IP of the Controller in {peer_region} is {ip}.")
    print(f"Checking port 443 on {ip}.")

    message = json.dumps(
        {
            "FailingPrivIP": ip,
            "FailingRegion": os.environ.get("peer_region"),
            "HealthCheckRule": os.environ.get("health_check_rule"),
            "LocalRegion": os.environ.get("region"),
            "Service": "Health Check",
        }
    )

    # print("Publishing Message to SNS")
    # publish_message_to_sns(sns_topic_arn, message, region)

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


def update_lamba_env_vars(function_name, region, key, value):
    client = boto3.client("lambda", region)
    response = client.get_function_configuration(FunctionName=function_name)
    current_env = response["Environment"]
    current_env["Variables"][key] = value
    response = client.update_function_configuration(
        FunctionName=function_name, Environment=current_env
    )
    return response


# def get_task_def_env_vars(region, task_def_family):
#     try:
#         ecs_client = boto3.client("ecs", region)
#         response = ecs_client.describe_task_definition(taskDefinition=task_def_family)
#     except Exception as e:
#         print(e)
#         sys.exit(1)

#     env = response["taskDefinition"]["containerDefinitions"][0]["environment"]
#     taskDefinitionArn = response["taskDefinition"]["taskDefinitionArn"]
#     print("taskDefinitionArn:", taskDefinitionArn)
#     env_dict = {pair["name"]: pair["value"] for pair in env}
#     return env_dict


# def get_ssm_parameter_value(path, region):
#     try:
#         ssm_client = boto3.client("ssm", region)
#         resp = ssm_client.get_parameter(Name=path, WithDecryption=True)
#         return resp["Parameter"]["Value"]
#     except Exception as e:
#         print(e)
#         sys.exit(1)


# mask = lambda input: input[0:5] + "*" * 15 if isinstance(input, str) else ""


# def get_api_token(ip_addr):
#     """Get API token from controller. Older controllers that don't support it will not have this
#     API or endpoints. We return None in that scenario to be backkward compatible"""
#     try:
#         data = requests.get(
#             f"https://{ip_addr}/v2/api?action=get_api_token", verify=False
#         )
#     except requests.exceptions.ConnectionError as err:
#         print("Can't connect to controller with IP %s. %s" % (ip_addr, str(err)))
#         raise AvxError(str(err)) from err
#     buf = data.content
#     if data.status_code not in [200, 404]:
#         err = f"Controller at {ip_addr} is not ready. Status code {data.status_code}  {buf}"
#         print(err)
#         raise AvxError(err)
#     try:
#         out = json.loads(buf)
#     except ValueError:
#         print(f"Token is probably not supported. Response is {buf}")
#         print("Did not obtain token")
#         return None
#     try:
#         api_return = out["return"]
#     except (KeyError, AttributeError, TypeError) as err:
#         print(
#             f"Getting return code failed due to {err}. Token may not be supported."
#             f"Response is {out}"
#         )
#         print("Did not obtain token")
#         return None
#     if api_return is False:
#         try:
#             reason = out["reason"]
#         except (KeyError, AttributeError, TypeError) as err:
#             print(f"Couldn't get reason. Response is {out}")
#             print("Did not obtain token")
#             return None
#         if reason == "RequestRefused":
#             err = f"Controller at {ip_addr} is not ready. Status code {reason} {out}"
#             print(err)
#             raise AvxError(err)
#         print(
#             f"Getting token failed due to {reason}. Token may not be supported."
#             f"Response is {out}"
#         )
#         print("Did not obtain token")
#         return None
#     try:
#         token = out["results"]["api_token"]
#     except (ValueError, AttributeError, TypeError, KeyError) as err:
#         print(f"Getting token failed due to {err}")
#         print(f"Token is probably not supported. Response is {out}")
#         print("Did not obtain token")
#         return None
#     print("Obtained token")
#     return token


# def login_to_controller(ip_addr, username, pwd):
#     """Logs into the controller and returns the cid"""
#     token = get_api_token(ip_addr)
#     headers = {}
#     base_url = "https://" + ip_addr + "/v1/api"
#     if token:
#         headers = {
#             "Content-Type": "application/x-www-form-urlencoded",
#             "X-Access-Key": token,
#         }
#         base_url = "https://" + ip_addr + "/v2/api"
#     try:
#         response = requests.post(
#             base_url,
#             verify=False,
#             headers=headers,
#             data={"username": username, "password": pwd, "action": "login"},
#         )
#     except Exception as err:
#         print(
#             "Can't connect to controller with elastic IP %s. %s" % (ip_addr, str(err))
#         )
#         raise AvxError(str(err)) from err
#     try:
#         response_json = response.json()
#     except ValueError as err:
#         print(f"response not in json {response}")
#         raise AvxError("Unable to create session. {}".format(response)) from err
#     try:
#         cid = response_json.pop("CID")
#         print("Created new session with CID {}\n".format(mask(cid)))
#     except KeyError as err:
#         print(response_json)
#         print("Unable to create session. {} {}".format(err, response_json))
#         raise AvxError("Unable to create session. {}".format(err)) from err
#     print(response_json)
#     return cid


# def is_controller_ready_v2(
#     ip_addr="123.123.123.123",
#     CID="ABCD1234",
# ):
#     start_time = time.time()
#     api_endpoint_url = "https://" + ip_addr + "/v2/api"
#     data = {"action": "is_controller_ready", "CID": CID}
#     print("API endpoint url:", str(api_endpoint_url))
#     payload_with_hidden_password = dict(data)
#     payload_with_hidden_password["CID"] = "************"
#     print(
#         f"Request payload: "
#         f"{str(json.dumps(obj=payload_with_hidden_password, indent=4))}"
#     )

#     while time.time() - start_time < 600:
#         try:
#             response = requests.get(
#                 url=api_endpoint_url, params=data, verify=False, timeout=60
#             )
#             if response is not None:
#                 py_dict = response.json()

#                 if response.status_code == 200 and py_dict["return"] is True:
#                     print(f"Controller is ready to operate")
#                     return True
#                     break
#             else:
#                 print(f"Controller is not ready")
#         except requests.Timeout:
#             print(f"The API request timed out after 60 seconds")
#         except Exception as err:
#             print(str(err))
#         print(f"Checking if controller is ready in 60 seconds.")
#         time.sleep(60)

#     print(f"Controller is not ready to operate")
#     return False
