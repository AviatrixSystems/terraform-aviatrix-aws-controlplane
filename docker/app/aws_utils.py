import time

TASK_DEF_FAMILY = "AVX_PLATFORM_HA"

def get_task_def(ecs_client):
    """this function returns the task definition"""
    current_task_def = ecs_client.describe_task_definition(
        taskDefinition=TASK_DEF_FAMILY, include=["TAGS"]
    )
    return current_task_def


def get_task_def_env(ecs_client):
    """this function returns the environment in the task definition"""
    current_task_def = get_task_def(ecs_client)
    task_def_env_dict = {
        item["name"]: item["value"]
        for item in current_task_def["taskDefinition"]["containerDefinitions"][0]["environment"]
    }
    return task_def_env_dict

def get_ec2_instance(ec2_client, inst_name="", inst_id=""):
    """given an instance ID or name, this function returns the EC2 instance"""
    attempts = 0
    retries = 5
    delay = 60
    instanceobj = {}
    if inst_id:
        id_tag = "instance-id"
        id_val = inst_id
    elif inst_name:
        id_tag = "tag:Name"
        id_val = inst_name
    else:
        print("Unable to find instance - no name or ID provided")
        return instanceobj
    while attempts <= retries:
        try:
            instanceobj = ec2_client.describe_instances(
                Filters=[
                    {"Name": "instance-state-name", "Values": ["running"]},
                    {"Name": id_tag, "Values": [id_val]},
                ]
            )["Reservations"][0]["Instances"][0]
            if instanceobj:
                break
        except Exception as err:
            print(f"Unable to find instance with '{id_tag}' - '{id_val}' -- {err} ")
        attempts += 1
        print(f"Retrying instance check attempt {attempts} in {delay} seconds")
        time.sleep(delay)
    return instanceobj
