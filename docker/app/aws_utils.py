TASK_DEF_FAMILY = "AVX_PLATFORM_HA"

def get_task_def_env(ecs_client):
    """this function returns the environment in the task definition"""
    current_task_def = ecs_client.describe_task_definition(
        taskDefinition=TASK_DEF_FAMILY,
    )
    print(f"get_task_def_env - {current_task_def}")
    task_def_env_dict = {
        item["name"]: item["value"]
        for item in current_task_def["taskDefinition"]["containerDefinitions"][0]["environment"]
    }
    return task_def_env_dict

def get_task_def_env_var(ecs_client, env_var=""):
    """Given an env var, this function returns the value in the task definition env"""
    if not env_var: return ""
    task_def_env = get_task_def_env(ecs_client)
    return task_def_env.get(env_var, "")
