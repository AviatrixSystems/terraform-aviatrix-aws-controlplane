TASK_DEF_FAMILY = "AVX_PLATFORM_HA"

def get_task_def(ecs_client):
    """this function returns the task definition"""
    current_task_def = ecs_client.describe_task_definition(
        taskDefinition=TASK_DEF_FAMILY, include=["TAGS"]
    )
    print(f"get_task_def - {current_task_def}")
    return current_task_def


def get_task_def_env(ecs_client):
    """this function returns the environment in the task definition"""
    current_task_def = get_task_def(ecs_client)
    task_def_env_dict = {
        item["name"]: item["value"]
        for item in current_task_def["taskDefinition"]["containerDefinitions"][0]["environment"]
    }
    return task_def_env_dict
