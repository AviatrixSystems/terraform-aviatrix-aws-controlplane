import boto3
import os
import time
import aws_controller
import aws_utils


HANDLE_HA_TIMEOUT = 1200
TASK_DEF_FAMILY = "AVX_PLATFORM_HA"
WAIT_DELAY = 30


def health_check_handler(local_region, failing_region):
    print("Using inter_region_v2 code")
    start_time = time.time()

    # Disable health check Lambda

    local_events_client = boto3.client("events", region_name=local_region)
    print(local_events_client.list_rules())

    print("Disabling health check rule")
    response = local_events_client.disable_rule(Name="aviatrix-healthcheck-rule")
    print(response)

    # 1. Fetching all env variables in between regions
    local_client = boto3.client("ec2", local_region)
    local_ecs_client = boto3.client("ecs", local_region)
    failing_client = boto3.client("ec2", failing_region)
    failing_ecs_client = boto3.client("ecs", failing_region)
    local_env_var = local_ecs_client.describe_task_definition(
        taskDefinition=TASK_DEF_FAMILY
    )["taskDefinition"]["containerDefinitions"][0]["environment"]
    failing_env_var = failing_ecs_client.describe_task_definition(
        taskDefinition=TASK_DEF_FAMILY
    )["taskDefinition"]["containerDefinitions"][0]["environment"]

    # Convert lists to dicts
    local_env = {env_var["name"]: env_var["value"] for env_var in local_env_var}
    failing_env = {env_var["name"]: env_var["value"] for env_var in failing_env_var}

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

    failing_private_ip = failing_env.get("PRIV_IP")

    print(f"failing_private_ip : {failing_private_ip}")

    local_priv_ip = local_env.get("PRIV_IP")

    print(f"local_priv_ip : {local_priv_ip}")

    # 3. Trying to find Instance in DR region
    if aws_controller.is_region2_latest_backup_file(local_priv_ip, failing_private_ip):
        s3_file = "CloudN_" + failing_private_ip + "_save_cloudx_config.enc"
        version_file = "CloudN_" + failing_private_ip + "_save_cloudx_version.txt"
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

        aws_controller.sync_env_var(failing_ecs_client, failing_env, {"STATE": "INIT"})

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
        print(response_json)
        if response_json["return"] == True:
            failover = "completed"

        # 5. Migrate IP

        if s3_ctrl_version and int(s3_ctrl_version.split(".")[0]) >= 7:
            if aws_controller.is_controller_ready_v2(local_priv_ip, cid) == True:
                print("START: Migrate IP")
                aws_controller.migrate_ip(local_priv_ip, cid, failing_env["EIP"])
                print("END: Migrate IP")
            else:
                print(
                    "Controller is still restoring, migrate previous ip: %s manually"
                    % failing_env["EIP"]
                )
        else:
            print(
                "Once the restore process is completed, migrate previous ip: %s manually"
                % failing_env["EIP"]
            )

        print("Update ACTIVE_REGION & STANDBY_REGION in DR ECS environment variables")
        aws_controller.sync_env_var(
            failing_ecs_client,
            failing_env,
            {
                "ACTIVE_REGION": local_region,
                "STANDBY_REGION": failing_region,
            },
        )

        print(
            "Update ACTIVE_REGION & STANDBY_REGION in primary ECS environment variables"
        )
        aws_controller.sync_env_var(
            local_ecs_client,
            local_env,
            {
                "ACTIVE_REGION": local_region,
                "STANDBY_REGION": failing_region,
            },
        )

        # Update environment so that ACTIVE_REGION and STANDBY_REGION are set correctly
        os.environ.update(
            {
                "ACTIVE_REGION": local_region,
                "STANDBY_REGION": failing_region,
            }
        )

        # Update Route 53
        aws_controller.update_record(
            local_env.get("ZONE_NAME"),
            local_env.get("RECORD_NAME"),
            local_env.get("CTRL_ASG"),
            local_region,
        )
        print(
            "Updating %s to point to the LB in %s"
            % (local_env.get("RECORD_NAME"), local_region)
        )

    finally:
        if s3_ctrl_version and s3_ctrl_version != failing_env.get("CTRL_INIT_VER"):
            init_ver = s3_ctrl_version
        else:
            init_ver = failing_env.get("CTRL_INIT_VER")
        # if failover and failover == "completed":
        #     state = "ACTIVE"
        # else:
        #     state = ""
        # if not dr_duplicate:
        #     print(f"Reverting sg {dr_sg_modified}")
        #     restored_access = aws_controller.restore_security_group_access(
        #         failing_client, dr_sg_modified, failing_ecs_client
        #     )
        #     if restored_access:
        #         aws_controller.update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": ""})
        # aws_controller.sync_env_var(
        #     failing_ecs_client,
        #     failing_env,
        #     {"CTRL_INIT_VER": init_ver, "TMP_SG_GRP": "", "STATE": state},
        # )
        print("- Completed function -")
