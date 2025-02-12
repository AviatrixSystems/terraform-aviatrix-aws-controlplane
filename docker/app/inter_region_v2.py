import boto3
import os
import socket
import time
import aws_controller
import aws_utils
from tenacity import retry, wait_fixed


HANDLE_HA_TIMEOUT = 1200
TASK_DEF_FAMILY = "AVX_PLATFORM_HA"
WAIT_DELAY = 30


def health_check_handler(msg_json):
    print("Using inter_region_v2 code")
    start_time = time.time()

    bucket_name_1 = msg_json.get("BucketName1")
    bucket_name_2 = msg_json.get("BucketName2")
    local_region = msg_json.get("LocalRegion")
    failing_region = msg_json.get("FailingRegion")
    health_check_rule = msg_json.get("HealthCheckRule")
    region1 = msg_json.get("Region1")
    region2 = msg_json.get("Region2")

    # Disable health check Lambda in local region
    local_events_client = boto3.client("events", region_name=local_region)
    print("Disabling health check rule in", local_region)
    response = local_events_client.disable_rule(Name=health_check_rule)
    print(response)

    # 1. Fetching all env variables in between regions
    local_client = boto3.client("ec2", local_region)
    local_ecs_client = boto3.client("ecs", local_region)

    local_env = fetch_environment_variables(local_region, TASK_DEF_FAMILY)
    failing_env = fetch_environment_variables(failing_region, TASK_DEF_FAMILY)

    # 2. Trying to find Instance in local region
    if local_env.get("INST_ID"):
        print(f"INST_ID: {local_env.get('INST_ID')}")
        local_instanceobj = aws_utils.get_ec2_instance(
            local_client, "", local_env.get("INST_ID")
        )
    elif local_env.get("AVIATRIX_TAG"):
        print(f"AVIATRIX_TAG : {local_env.get('AVIATRIX_TAG')}")
        local_instanceobj = aws_utils.get_ec2_instance(
            local_client, local_env.get("AVIATRIX_TAG"), ""
        )
    else:
        local_instanceobj = {}

    if local_instanceobj == {}:
        raise aws_controller.AvxError(f"Cannot find Controller in {local_region}")

    failing_private_ip = msg_json.get("FailingPrivIP")
    print(f"failing_private_ip : {failing_private_ip}")

    local_priv_ip = local_env.get("PRIV_IP")
    print(f"local_priv_ip : {local_priv_ip}")

    if check_port(local_priv_ip, 443):
        print("Successfully connected to", local_priv_ip)
    else:
        print("Failed to connect to", local_priv_ip)
        print("Retrieving private IP from Controller object", local_instanceobj)
        local_priv_ip = local_instanceobj.get("NetworkInterfaces")[0].get(
            "PrivateIpAddress"
        )
        print(
            "Updated local_priv_ip to",
            local_instanceobj.get("NetworkInterfaces")[0].get("PrivateIpAddress"),
        )

    failing_eip = msg_json.get("FailingEIP")
    print(f"failing_eip : {failing_eip}")

    # 3. Trying to find Instance in DR region
    try:
        print("Checking S3 bucket:", os.environ.get("S3_BUCKET_BACK"))
        if aws_controller.is_region2_latest_backup_file(
            local_priv_ip,
            failing_private_ip,
            os.environ.get("S3_BUCKET_REGION"),
            os.environ.get("S3_BUCKET_BACK"),
        ):
            s3_file = "CloudN_" + failing_private_ip + "_save_cloudx_config.enc"
            version_file = "CloudN_" + failing_private_ip + "_save_cloudx_version.txt"
        else:
            s3_file = "CloudN_" + local_priv_ip + "_save_cloudx_config.enc"
            version_file = "CloudN_" + local_priv_ip + "_save_cloudx_version.txt"
    except Exception as err:
        print(err)
        if os.environ.get("ENABLE_SECONDARY_BACKUP") == "true":
            print("enable_secondary_backup is true, retrying in secondary region")
            print("Checking S3 bucket:", os.environ.get("S3_BUCKET_BACK2"))
            if aws_controller.is_region2_latest_backup_file(
                local_priv_ip,
                failing_private_ip,
                os.environ.get("S3_BUCKET_REGION2"),
                os.environ.get("S3_BUCKET_BACK2"),
            ):
                s3_file = "CloudN_" + failing_private_ip + "_save_cloudx_config.enc"
                version_file = (
                    "CloudN_" + failing_private_ip + "_save_cloudx_version.txt"
                )
            else:
                s3_file = "CloudN_" + local_priv_ip + "_save_cloudx_config.enc"
                version_file = "CloudN_" + local_priv_ip + "_save_cloudx_version.txt"

    print("API Access to Controller will use IP : " + str(local_priv_ip))

    total_time = 0

    if os.environ.get("AVX_PASSWORD", "") == "":
        creds = aws_controller.get_ssm_parameter_value(
            os.environ.get("AVX_PASSWORD_SSM_PATH"),
            os.environ.get("AVX_PASSWORD_SSM_REGION"),
        )
    else:
        creds = os.environ.get("AVX_PASSWORD", "")

    try:
        try:
            failing_ecs_client = boto3.client("ecs", failing_region)
            aws_controller.sync_env_var(
                failing_ecs_client, failing_env, {"STATE": "INIT"}
            )
        except Exception as err:
            print(
                "Unable to sync environment variables in",
                failing_region,
                err,
            )

        # while total_time <= MAX_LOGIN_TIMEOUT:
        while time.time() - start_time < HANDLE_HA_TIMEOUT:
            try:
                cid = aws_controller.login_to_controller(local_priv_ip, "admin", creds)
                s3_ctrl_version = aws_controller.retrieve_controller_version(
                    version_file, local_priv_ip, cid
                )
            except Exception as err:
                print(str(err))
                print("Login failed, trying again in " + str(WAIT_DELAY))
                total_time += WAIT_DELAY
                time.sleep(WAIT_DELAY)
            else:
                break

        # 5. Upgrade controller if needed
        if s3_ctrl_version != aws_controller.controller_version(local_priv_ip, cid):
            print(f"Upgrading controller to {s3_ctrl_version}")
            aws_controller.upgrade_controller(local_priv_ip, cid, s3_ctrl_version)

        # Restore controller
        cid = aws_controller.login_to_controller(local_priv_ip, "admin", creds)
        response_json = aws_controller.restore_backup(
            cid, local_priv_ip, s3_file, local_env["PRIMARY_ACC_NAME"]
        )
        print("Restore backup response:", response_json)
        if response_json["return"] == True:
            failover = "completed"

        ## Create a new backup so that filename uses new_private_ip
        if response_json.get("return", False) is True:
            print("Successfully restored backup")

            # If restore succeeded, update private IP to that of the new instance now.
            print("Creating new backup")
            aws_controller.setup_ctrl_backup(
                local_priv_ip, cid, local_env["PRIMARY_ACC_NAME"], "true"
            )

        # 5. Migrate IP

        if s3_ctrl_version and int(s3_ctrl_version.split(".")[0]) >= 7:
            if aws_controller.is_controller_ready_v2(local_priv_ip, cid) == True:
                print("START: Migrate IP")
                aws_controller.migrate_ip(local_priv_ip, cid, failing_eip)
                print("END: Migrate IP")
            else:
                print(
                    "Controller is still restoring, migrate previous ip: %s manually"
                    % failing_eip
                )
        else:
            print(
                "Once the restore process is completed, migrate previous ip: %s manually"
                % failing_eip
            )

        # Initiate failover
        print(
            "Updating %s to the Controller in %s"
            % (local_env.get("RECORD_NAME"), local_region)
        )

        # Clear cached values in Lambda environment variables
        print("Clearing cached values for peer_priv_ip and peer_eip")
        response = update_lamba_env_vars(
            "aviatrix-ha-healthcheck", local_region, "peer_priv_ip", ""
        )
        print("Clearing peer_priv_ip reponse:", response)
        response = update_lamba_env_vars(
            "aviatrix-ha-healthcheck", local_region, "peer_eip", ""
        )
        print("Clearing peer_ip response:", response)

        # Update ECS environment variables
        print("Update ACTIVE_REGION & STANDBY_REGION in new active region")
        aws_controller.sync_env_var(
            local_ecs_client,
            local_env,
            {
                "ACTIVE_REGION": local_region,
                "STANDBY_REGION": failing_region,
            },
        )

        # Creating a file in S3 causes the standby in region2 to take over.
        # Deleting the file in S3 reverts back to region1.
        if failing_region == region1:
            print(
                "Failing region is region1 %s. Creating failover trigger file in S3."
                % region1
            )
            create_file_in_s3(bucket_name_1, "initiate-failover.html", "aviatrix-ha")
            create_file_in_s3(bucket_name_2, "initiate-failover.html", "aviatrix-ha")

        else:
            print(
                "Failing region is region2 %s. Deleting failover trigger file from S3."
                % region2
            )
            delete_file_from_s3(bucket_name_1, "initiate-failover.html")
            delete_file_from_s3(bucket_name_2, "initiate-failover.html")

        # Enable health check Lambda in failing region
        response = enable_health_check(failing_region, health_check_rule)
        print(response)

    finally:
        if s3_ctrl_version and s3_ctrl_version != failing_env.get("CTRL_INIT_VER", ""):
            init_ver = s3_ctrl_version
        else:
            init_ver = failing_env.get("CTRL_INIT_VER", "")
        if failover and failover == "completed":
            state = "ACTIVE"
        else:
            state = ""
        # if not dr_duplicate:
        #     print(f"Reverting sg {dr_sg_modified}")
        #     restored_access = aws_controller.restore_security_group_access(
        #         failing_client, dr_sg_modified, failing_ecs_client
        #     )
        #     if restored_access:
        #         aws_controller.update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": ""})
        try:

            # PRIV_IP may have changed while this code was running
            # so try to refetch the env vars from the failing region
            updated_failing_env = fetch_environment_variables(
                failing_region, TASK_DEF_FAMILY
            )

            if updated_failing_env != {}:
                failing_env = updated_failing_env

            failing_ecs_client = boto3.client("ecs", failing_region)

            aws_controller.sync_env_var(
                failing_ecs_client,
                failing_env,
                {
                    "ACTIVE_REGION": local_region,
                    "STANDBY_REGION": failing_region,
                    "CTRL_INIT_VER": init_ver,
                    "STATE": state,
                },
            )
        except:
            print(
                "Unable to update ACTIVE_REGION & STANDBY_REGION in new standby region"
            )
        print("- Completed function -")


# Enable health check in failing region to monitor new Controller
# Retry indefinitely because the failing region may be inaccessible at this point
@retry
def enable_health_check(region, rule):
    print("Enabling health check rule in", region)
    events_client = boto3.client("events", region_name=region)
    response = events_client.enable_rule(Name=rule)
    return response


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


def create_file_in_s3(bucket_name, file_name, file_content):
    s3 = boto3.client("s3")
    try:
        s3.put_object(Body=file_content, Bucket=bucket_name, Key=file_name)
        print(f"File {file_name} successfully created in {bucket_name}")
    except Exception as e:
        print(f"Error creating file: {e}")


# The delete needs to be retried indefinitely otherwise it will cause an incorrect
# Route 53 failover when the S3 bucket becomes accessible again.
@retry(wait=wait_fixed(60))
def delete_file_from_s3(bucket_name, file_name):
    s3 = boto3.client("s3")
    try:
        s3.delete_object(Bucket=bucket_name, Key=file_name)
        print(f"File {file_name} successfully deleted from {bucket_name}")
    except Exception as e:
        print(f"Error deleting file: {e}")
        raise (Exception)


def fetch_environment_variables(region, task_def_family):
    """
    Fetches environment variables for a given ECS task definition.
    """
    try:
        client = boto3.client("ecs", region)
        container_definitions = client.describe_task_definition(
            taskDefinition=task_def_family
        )["taskDefinition"]["containerDefinitions"]
        return {
            env["name"]: env["value"] for env in container_definitions[0]["environment"]
        }
    except Exception as e:
        print(f"Error fetching environment variables: {e}")
        return {}


def check_port(ip, port, retries=3, interval=60, timeout=5):
    try:
        for i in range(retries):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))

            if result == 0:
                print(f"Successfully connected to {ip} on port {port}.")
                return True

            if i < retries - 1:
                print(
                    f"Failed to connect to {ip} on port {port}. Sleeping for {interval} seconds."
                )
                time.sleep(interval)
            else:
                print(
                    f"Failed to connect to {ip} on port {port} after {retries} retries."
                )
        return False
    except:
        print(f"Failed to connect to {ip} on port {port}.")
        return False
    finally:
        s.close()
