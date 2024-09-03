import boto3
import os
import time
import aws_controller
import aws_utils


HANDLE_HA_TIMEOUT = 1200
TASK_DEF_FAMILY = "AVX_PLATFORM_HA"
WAIT_DELAY = 30


def health_check_handler(pri_region, dr_region):
    print("Using inter_region_v2 code")
    start_time = time.time()

    # Disable health check Lambda

    client = boto3.client("events", region_name="us-east-2")
    print(client.list_rules())

    print("Disabling health check rule")
    response = client.disable_rule(Name="aviatrix-healthcheck-rule")
    print(response)

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
        dr_instanceobj = aws_utils.get_ec2_instance(
            dr_client, "", dr_env.get("INST_ID")
        )
    elif dr_env.get("AVIATRIX_TAG"):
        print(f"AVIATRIX_TAG : {dr_env.get('AVIATRIX_TAG')}")
        dr_instanceobj = aws_utils.get_ec2_instance(
            dr_client, dr_env.get("AVIATRIX_TAG"), ""
        )
    else:
        dr_instanceobj = {}

    if dr_instanceobj == {}:
        raise aws_controller.AvxError(f"Cannot find Controller in {dr_region}")

    dr_private_ip = dr_instanceobj.get("NetworkInterfaces")[0].get("PrivateIpAddress")
    priv_ip = pri_env.get("PRIV_IP")
    print(f"Priv_ip : {priv_ip}")
    print(f"dr_private_ip : {dr_private_ip}")

    # 3. Trying to find Instance in DR region
    if aws_controller.is_region2_latest_backup_file(priv_ip, dr_private_ip):
        s3_file = "CloudN_" + dr_private_ip + "_save_cloudx_config.enc"
        version_file = "CloudN_" + dr_private_ip + "_save_cloudx_version.txt"
    else:
        s3_file = "CloudN_" + priv_ip + "_save_cloudx_config.enc"
        version_file = "CloudN_" + priv_ip + "_save_cloudx_version.txt"

    dr_api_ip = dr_instanceobj["PublicIpAddress"]
    print("DR API Access to Controller will use IP : " + str(dr_api_ip))
    api_private_access = dr_env["API_PRIVATE_ACCESS"]

    # # 4. Temp security group access
    # dr_duplicate, dr_sg_modified = aws_controller.temp_add_security_group_access(
    #     dr_client, dr_instanceobj, api_private_access
    # )
    # if not dr_duplicate:
    #     aws_controller.update_env_dict(dr_ecs_client, {"CONTROLLER_TMP_SG_GRP": dr_sg_modified})
    #     print(
    #         f"created tmp access - updated CONTROLLER_TMP_SG_GRP: {os.environ.items()}"
    #     )
    # print(
    #     "0.0.0.0/0:443 rule is %s present %s"
    #     % (
    #         "already" if dr_duplicate else "not",
    #         "" if dr_duplicate else ". Modified Security group %s" % dr_sg_modified,
    #     )
    # )
    total_time = 0

    if os.environ.get("AVX_PASSWORD", "") == "":
        creds = aws_controller.get_ssm_parameter_value(
            os.environ.get("AVX_PASSWORD_SSM_PATH"),
            os.environ.get("AVX_PASSWORD_SSM_REGION"),
        )
    else:
        creds = os.environ.get("AVX_PASSWORD", "")

    # Check if this is the Active or Standby region
    if pri_region == pri_env.get("ACTIVE_REGION"):
        print("This event happened in the active region:", pri_env.get("ACTIVE_REGION"))

        try:
            # if not dr_duplicate:
            #     aws_controller.sync_env_var(
            #         dr_ecs_client,
            #         dr_env,
            #         {"TMP_SG_GRP": dr_sg_modified, "STATE": "INIT"},
            #     )
            # else:
            aws_controller.sync_env_var(dr_ecs_client, dr_env, {"STATE": "INIT"})

            # while total_time <= MAX_LOGIN_TIMEOUT:
            while time.time() - start_time < HANDLE_HA_TIMEOUT:
                try:
                    cid = aws_controller.login_to_controller(dr_api_ip, "admin", creds)
                    s3_ctrl_version = aws_controller.retrieve_controller_version(
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
            if s3_ctrl_version != aws_controller.controller_version(dr_api_ip, cid):
                print(f"Upgrading controller to {s3_ctrl_version}")
                aws_controller.upgrade_controller(dr_api_ip, cid, s3_ctrl_version)

            # Restore controller
            cid = aws_controller.login_to_controller(dr_api_ip, "admin", creds)
            response_json = aws_controller.restore_backup(
                cid, dr_api_ip, s3_file, pri_env["PRIMARY_ACC_NAME"]
            )
            print(response_json)
            if response_json["return"] == True:
                failover = "completed"

            # 5. Migrate IP

            if s3_ctrl_version and int(s3_ctrl_version.split(".")[0]) >= 7:
                if aws_controller.is_controller_ready_v2(dr_api_ip, cid) == True:
                    print("START: Migrate IP")
                    aws_controller.migrate_ip(dr_api_ip, cid, pri_env["EIP"])
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
            aws_controller.sync_env_var(
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
            aws_controller.sync_env_var(
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
            aws_controller.update_record(
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
            # if failover and failover == "completed":
            #     state = "ACTIVE"
            # else:
            #     state = ""
            # if not dr_duplicate:
            #     print(f"Reverting sg {dr_sg_modified}")
            #     restored_access = aws_controller.restore_security_group_access(
            #         dr_client, dr_sg_modified, dr_ecs_client
            #     )
            #     if restored_access:
            #         aws_controller.update_env_dict(ecs_client, {"CONTROLLER_TMP_SG_GRP": ""})
            # aws_controller.sync_env_var(
            #     dr_ecs_client,
            #     dr_env,
            #     {"CTRL_INIT_VER": init_ver, "TMP_SG_GRP": "", "STATE": state},
            # )
            print("- Completed function -")

    elif pri_region == pri_env.get("STANDBY_REGION"):
        print(
            "This event happened in the standby region:", pri_env.get("STANDBY_REGION")
        )
