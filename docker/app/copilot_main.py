import boto3
import time
import datetime
import traceback
import single_copilot_lib as single_cplt
import cluster_copilot_lib as cluster_cplt

def get_ssm_parameter_value(path, region):
    try:
        ssm_client = boto3.client("ssm", region)
        resp = ssm_client.get_parameter(Name=path, WithDecryption=True)
        return resp["Parameter"]["Value"]
    except Exception as err:
        raise (f"Error fetching from ssm")

def controller_copilot_setup(api, event):
  # enable copilot association
  print("Associate Aviatrix CoPilot with Aviatrix Controller")
  api.enable_copilot_association(event['copilot_info']['private_ip'], event['copilot_info']['public_ip'])
  response = api.get_copilot_association_status()
  print(f"get_copilot_association_status: {response}")
  # enable netflow
  print("Enable Netflow Agent configuration on Aviatrix Controller")
  api.enable_netflow_agent(event['copilot_info']['public_ip'])
  # api.enable_netflow_agent(copilot_info["private_ip"])
  response = api.get_netflow_agent()
  print(f"get_netflow_agent: {response}")
  # enable syslog
  print("Enable Remote Syslog configuration on Aviatrix Controller")
  # api.enable_syslog_configuration(copilot_info["private_ip"])
  api.enable_syslog_configuration(event['copilot_info']['public_ip'])
  response = api.get_remote_syslog_logging_status()
  print(f"get_remote_syslog_logging_status: {response}")
  print("Enable CoPilot SG management on Aviatrix Controller")
  # api.enable_copilot_sg(copilot_info["private_ip"])
  api.enable_copilot_sg(event['primary_account_name'],
                        "1",
                        event['region'],
                        event['copilot_info']['vpc_id'],
                        event['copilot_info']['instance_id'])
  response = api.wait_and_get_copilot_sg_status()
  print(f"get_copilot_sg_status: {response}")

def get_vm_password(env, pass_type="copilot"):
  if pass_type == "copilot" and env["COP_EMAIL"] != "" and env["COP_USERNAME"] != "":
    if env["AVX_COP_PASSWORD"] == "":
        # Fetch Aviatrix CoPilot credentials from encrypted SSM parameter store
        password = get_ssm_parameter_value(
          env["AVX_COPILOT_PASSWORD_SSM_PATH"],
          env["AVX_PASSWORD_SSM_REGION"],
        )
    else:
        password = env["AVX_COP_PASSWORD"]
  else:
    if env["AVX_PASSWORD"] == "":
        # Fetch Aviatrix Controller credentials from encrypted SSM parameter store
        password =get_ssm_parameter_value(
          env["AVX_PASSWORD_SSM_PATH"],
          env["AVX_PASSWORD_SSM_REGION"],
        )
    else:
        password = env["AVX_PASSWORD"]
  return password

def get_copilot_user_info(env):
  # get copilot user info
  user_info = {}
  user_info["password"] = get_vm_password(env)
  if env["COP_EMAIL"] != "" and env["COP_USERNAME"] != "":
    user_info["username"] = env["COP_USERNAME"]
    user_info["email"] = env["COP_EMAIL"]
    user_info["user_groups"] = ["admin"]  # hardcode copilot user group
    user_info["custom_user"] = True
  else:
    user_info["username"] = "admin"
    user_info["email"] = ""
    user_info["user_groups"] = []
    user_info["custom_user"] = False
  return user_info

def get_restore_region(env):
  # determine restore region based on event type
  if get_copilot_inter_region(env) and not get_copilot_init(env):
    print(f"inter-region HA in current region '{get_current_region(env)}'")
    if get_instance_recent_restart(env, "controller"):
      restore_region = get_dr_region(env)
      print(f"Controller was also restarted recently, so we will assume regional failure")
      print(f"restore controller and copilot to dr region'{restore_region}'")
    else:
      restore_region = get_current_region(env)
      print(f"HA event in an inter-region deployment, but the controller was not restarted recently. We will assume that only the CoPilot VM failed")
      print(f"restore copilot in current region because assuming controller did not fail in inter-region HA: '{restore_region}'")
  else:
    restore_region = get_current_region(env)
    if get_copilot_inter_region(env):
      print(f"inter-region init - create in current region: '{restore_region}'")
      print(f"current region '{get_current_region(env)}' is inter-region primary '{get_active_region(env)}'")
    else:
      print(f"intra-region init/HA - create/restore in current region: '{restore_region}'")
  return restore_region

def get_copilot_init(env):
  return False if "PRIV_IP" in env else True

def get_active_region(env):
  if get_copilot_inter_region(env):
    if "ACTIVE_REGION" in env:
      return env["ACTIVE_REGION"]
    else:
      print(f"Inter-region deployment, but unable to find ACTIVE_REGION key: {env}")
  else:
    print(f"Not inter-region deployment - no ACTIVE_REGION in intra-region")

def get_copilot_inter_region(env):
  if "INTER_REGION" in env and env["INTER_REGION"] == "True":
    return True
  else:
    return False

def get_current_region(env):
  return env["SQS_QUEUE_REGION"]

def get_standby_region(env):
  return env["STANDBY_REGION"]

def get_dr_region(env):
  return env["DR_REGION"]

def get_controller_copilot_public_ips(env, controller, copilot):
  public_ips = {}
  # determine correct controller/copilot IPs based on event
  if get_copilot_inter_region(env) and not get_copilot_init(env):
    public_ips["copilot_public_ip"] = copilot["PublicIpAddress"]
    public_ips["controller_public_ip"] = controller["PublicIpAddress"]
  else:
    public_ips["copilot_public_ip"] = env["COP_EIP"]
    public_ips["controller_public_ip"] = env["EIP"]
  return public_ips

def get_copilot_auth_ip(env, public_ips, controller):
  # get the auth IP that will be used by copilot
  if "COP_AUTH_IP" in env and env["COP_AUTH_IP"] == "private":
    copilot_auth_ip = controller["PrivateIpAddress"]
  else:
    copilot_auth_ip = public_ips["controller_public_ip"]

  return copilot_auth_ip

def get_instance_recent_restart(env, type):
    curr_region = get_current_region(env)
    if type == "controller":
        instance_name = env["AVIATRIX_TAG"]
    else:
        instance_name = env["AVIATRIX_COP_TAG"]
    # Retrieve the launch time of the current region instance by instance name
    curr_region_client = boto3.client("ec2", curr_region)
    # get current region instance
    instanceobj = curr_region_client.describe_instances(
        Filters=[
            {"Name": "instance-state-name", "Values": ["running"]},
            {"Name": "tag:Name", "Values": [instance_name]},
        ]
    )["Reservations"][0]["Instances"][0]
    launch_time = instanceobj["LaunchTime"]
    # Calculate the time difference between the launch time and current time
    delta = datetime.datetime.now(datetime.timezone.utc) - launch_time
    # Check if the instance was recently restarted (e.g. within the last 10 minutes)
    if delta < datetime.timedelta(minutes=30):
        return True
    else:
        return False

def log_failover_status(env, type):
    if type == "controller":
        recent_reboot_log = "The Controller instance was recently restarted."
        no_recent_reboot_log = "The Controller instance was not recently restarted. If this is an inter-region deployment, there may be a disconnect between the Controller and the CoPilot. Please verify the assocation manually."
    else:
        recent_reboot_log = "The CoPilot instance was recently restarted."
        no_recent_reboot_log = "The CoPilot instance was not recently restarted. If this is an inter-region deployment, there may be a disconnect between the Controller and the CoPilot. Please verify the assocation manually."
    if get_instance_recent_restart(env, type):
        print(recent_reboot_log)
    else:
        print(no_recent_reboot_log)


def handle_copilot_ha(env):
  # use cases:
  # intra-region init
  #   assign pri copilot eip
  #    restore copilot
  # intra-region ha
  #   assign pri copilot eip
  #    restore copilot
  # inter-region init in primary region
  #   assign pri copilot eip
  #   restore pri region copilot
  # inter-region init in standby region
  #   assign pri copilot eip
  #   return
  # inter-region ha in primary region
  #   assign pri copilot eip
  #   restore to dr region copilot with dr controller
  # inter-region ha in secondary region
  #   assign pri copilot eip
  #   restore to pri region copilot with pri controller

  # get env information
  inter_region = get_copilot_inter_region(env)
  copilot_init = get_copilot_init(env)
  cop_deployment = env["COP_DEPLOYMENT"]

  # return if inter-region init in current region is standby_region
  if inter_region and copilot_init and get_current_region(env) == get_standby_region(env):
    print(f"Not initializing copilot in the standby region '{get_current_region(env)}' in inter-region init")
    return

  # log controller failover status
  try:
    log_failover_status(env, "controller")
  except Exception as err:
    print(f"Logging controller failover status failed with the error below.")
    print(str(err))

  # sleep
  print("sleeping for 900 seconds")
  time.sleep(900)

  # get controller instance and auth info
  controller_instance_name = env["AVIATRIX_TAG"]
  controller_username = "admin"
  controller_creds = get_vm_password(env, "controller")

  restore_region = get_restore_region(env)
  restore_client = boto3.client("ec2", restore_region)
  copilot_user_info = get_copilot_user_info(env)

  # get copilot instance and auth info
  env["copilot_data_node_regions"] = []
  env["copilot_data_node_usernames"] = []
  env["copilot_data_node_passwords"] = []
  env["copilot_data_node_volumes"] = []
  if cop_deployment == "fault-tolerant":
    instance_name = f"{env['AVIATRIX_COP_TAG']}-Main"
    for node_name in env[copilot_data_node_instance_names]:
      env[copilot_data_node_regions].append(restore_region)
      env[copilot_data_node_usernames].append(copilot_user_info['username'])
      env[copilot_data_node_passwords].append(copilot_user_info['password'])
      env[copilot_data_node_volumes].append('/dev/sda2')
  else:
    instance_name = env["AVIATRIX_COP_TAG"]


  # get restore_region (main) copilot to be created/restored
  copilot_instanceobj = restore_client.describe_instances(
    Filters=[
      {"Name": "instance-state-name", "Values": ["running"]},
      {"Name": "tag:Name", "Values": [instance_name]},
    ]
  )["Reservations"][0]["Instances"][0]
  print(f"copilot_instanceobj: {copilot_instanceobj}")

  # get restore region controller
  controller_instanceobj = restore_client.describe_instances(
    Filters=[
      {"Name": "instance-state-name", "Values": ["running"]},
      {"Name": "tag:Name", "Values": [controller_instance_name]},
    ]
  )["Reservations"][0]["Instances"][0]
  print(f"controller_instanceobj: {controller_instanceobj}")

  instance_public_ips = get_controller_copilot_public_ips(env, controller_instanceobj, copilot_instanceobj)
  copilot_auth_ip = get_copilot_auth_ip(env, instance_public_ips, controller_instanceobj)

  copilot_event = {
    "region": restore_region,
    "copilot_init": copilot_init,
    "cluster_ha_main_node": True,
    "primary_account_name": env["PRIMARY_ACC_NAME"],
    "auth_ip": copilot_auth_ip, # values should controller public or private IP
    "copilot_type": env['COP_DEPLOYMENT'],  # values should be "singleNode" or "fault-tolerant"
    "copilot_custom_user": copilot_user_info["custom_user"], # true/false based on copilot service account
    "copilot_data_node_public_ips": env[copilot_data_node_public_ips],  # cluster data nodes public IPs
    "copilot_data_node_private_ips": env[copilot_data_node_private_ips],  # cluster data nodes private IPs
    "copilot_data_node_regions": env[copilot_data_node_regions],  # cluster data nodes regions (should be the same)
    "copilot_data_node_names": env[copilot_data_node_names],  # names to be displayed in copilot cluster info
    "copilot_data_node_usernames": env[copilot_data_node_volumes], # cluster data nodes auth info
    "copilot_data_node_passwords": env[copilot_data_node_volumes], # cluster data nodes auth info
    "copilot_data_node_volumes": env[copilot_data_node_volumes],  # linux volume names (eg "/dev/sdf") - can be the same
    "copilot_data_node_sg_names": env[copilot_data_node_sg_names],  # cluster data nodes security group names
    "controller_info": {
        "public_ip": instance_public_ips["controller_public_ip"],
        "private_ip": controller_instanceobj["PrivateIpAddress"],
        "username": controller_username,
        "password": controller_creds,
        "sg_id": controller_instanceobj["SecurityGroups"][0]["GroupId"],  # controller security group ID
        "sg_name": controller_instanceobj["SecurityGroups"][0]["GroupName"],  # controller security group name
        "instance_id": controller_instanceobj["InstanceId"],
        "vpc_id": controller_instanceobj["VpcId"],
    },
    "copilot_info": {
        "public_ip": instance_public_ips["copilot_public_ip"],
        "private_ip": copilot_instanceobj["PrivateIpAddress"],
        "user_info": copilot_user_info,
        "sg_id": copilot_instanceobj["SecurityGroups"][0]["GroupId"],  # (main) copilot security group ID
        "sg_name": copilot_instanceobj["SecurityGroups"][0]["GroupName"],  # (main) copilot security group name
        "instance_id": copilot_instanceobj["InstanceId"],
        "vpc_id": copilot_instanceobj["VpcId"],
    },
  }
  print(f"copilot_event: {copilot_event}")
  
  handle_event(copilot_event)


def handle_event(event):
  # Preliminary actions - wait for CoPilot instances to be ready
  print(f"Starting CoPilot HA with copilot_init = '{event['copilot_init']}' and copilot_type = '{event['copilot_type']}'")
  ec2_client = boto3.client("ec2", region_name=event['region'])

  # Security group adjustment
  if event['copilot_type'] == "singleNode":
    print(f"Adding CoPilot IPs '{event['copilot_info']['public_ip']}' and '{event['copilot_info']['private_ip']}' to Controller SG '{event['controller_info']['sg_id']}'")
    try:
      single_cplt.authorize_security_group_ingress(ec2_client,
                                                  event['controller_info']['sg_id'],
                                                  443, 443, 'tcp',
                                                  [f"{event['copilot_info']['public_ip']}/32"])
      single_cplt.authorize_security_group_ingress(ec2_client,
                                                  event['controller_info']['sg_id'],
                                                  443, 443, 'tcp',
                                                  [f"{event['copilot_info']['private_ip']}/32"])
    except Exception as err:  # pylint: disable=broad-except
      print(str(traceback.format_exc()))
      print("Adding CoPilot IP to Controller SG failed due to " + str(err))
    try:
      print(f"Adding Controller auth IP '{event['auth_ip']}' to CoPilot SG '{event['copilot_info']['sg_id']}'")
      single_cplt.authorize_security_group_ingress(ec2_client,
                                                  event['copilot_info']['sg_id'],
                                                  443, 443, 'tcp',
                                                  [f"{event['auth_ip']}/32"])
    except Exception as err:  # pylint: disable=broad-except
      print(str(traceback.format_exc()))
      print("Adding Controller auth IP to CoPilot SG failed due to " + str(err))
  elif event['copilot_type'] == "fault-tolerant":
    cluster_cplt.manage_sg_rules(ec2_client,
                                 controller_sg_name=event['controller_info']['sg_name'],
                                 main_copilot_sg_name=event['copilot_info']['sg_name'],
                                 node_copilot_sg_names=event['copilot_data_node_sg_names'],
                                 controller_private_ip=event['controller_info']['private_ip'],
                                 main_copilot_public_ip=event['copilot_info']['public_ip'],
                                 node_copilot_public_ips=event['copilot_data_node_public_ips'],
                                 main_copilot_private_ip=event['copilot_info']['private_ip'],
                                 node_copilot_private_ips=event['copilot_data_node_private_ips'],
                                 cluster_init=event['copilot_init'],
                                 private_mode=False,
                                 add=True)

  api = single_cplt.ControllerAPI(controller_ip=event['controller_info']['public_ip'])
  # make sure controller sg is open
  api.manage_sg_access(ec2_client, event['controller_info']['sg_id'], True)
  # if custom copilot user is needed, login with the controller user,
  # and then create the copilot user
  if event["copilot_custom_user"]:
    api.retry_login(username=event['controller_info']['username'], password=event['controller_info']['password'])
    add_user_resp = api.add_account_user(event['copilot_info']['user_info'])
    print(f"Sleep for 20 seconds after adding user. add_user_resp: {add_user_resp}")
    time.sleep(20)

  # login with copilot user
  api.retry_login(username=event['copilot_info']['user_info']['username'],
                  password=event['copilot_info']['user_info']['password'])

  copilot_api = single_cplt.CoPilotAPI(copilot_ip=event['copilot_info']['public_ip'], cid=api._cid)
  
  # set the new copilot to use the controller to verify logins
  print(f"Set controller auth IP '{event['auth_ip']}' on CoPilot")
  set_controller_ip_resp = copilot_api.retry_set_controller_ip(event["auth_ip"],
                                                               event["copilot_info"]['user_info']["username"],
                                                               event["copilot_info"]['user_info']["password"])
  print(f"set_controller_ip: {set_controller_ip_resp}")

  # make sure controller sg is open
  api.manage_sg_access(ec2_client, event['controller_info']['sg_id'], True)

  if event['copilot_init']:
    # copilot init use case - not HA
    if event['copilot_type'] == "singleNode":
      # singleNode copilot init
      print("SingleNode CoPilot Initialization begin ...")
      response = copilot_api.init_copilot_single_node(event['copilot_info']['user_info']['username'],
                                                      event['copilot_info']['user_info']['password'])
      print(f"singlenode_copilot_init: {response}")
      copilot_api.wait_copilot_init_complete(event['copilot_type'])
    else:
      # Fault Tolerant copilot init
      print("Fault Tolerant CoPilot Initialization begin ...")
      cluster_event = {
        "ec2_client": ec2_client,
        "controller_public_ip": event['controller_info']['public_ip'],
        "controller_private_ip": event['controller_info']['private_ip'],
        "controller_region": event['region'],
        "controller_username": event['controller_info']['username'],
        "controller_password": event['controller_info']['password'],
        "main_copilot_public_ip": event['copilot_info']['public_ip'],
        "main_copilot_private_ip": event['copilot_info']['private_ip'],
        "main_copilot_region": event['region'],
        "main_copilot_username": event['copilot_info']['user_info']['username'],
        "main_copilot_password": event['copilot_info']['user_info']['password'],
        "node_copilot_public_ips": event['copilot_data_node_public_ips'],
        "node_copilot_private_ips": event['copilot_data_node_private_ips'],
        "node_copilot_regions": event['copilot_data_node_regions'],
        "node_copilot_usernames": event['copilot_data_node_usernames'],
        "node_copilot_passwords": event['copilot_data_node_passwords'],
        "node_copilot_data_volumes": event['copilot_data_node_volumes'],
        "node_copilot_names": event['copilot_data_node_names'],
        "private_mode": False,
        "controller_sg_name": event['controller_info']['sg_name'],
        "main_copilot_sg_name": event['copilot_info']['sg_name'],
        "node_copilot_sg_names": event['copilot_data_node_sg_names']
      }
      cluster_cplt.function_handler(cluster_event)
  else:
    # copilot HA use case
    if event['copilot_type'] == "singleNode" or event['cluster_ha_main_node']:
      # singleNode copilot HA
      # 1. get saved config from controller
      print(f"SingleNode CoPilot HA OR Cluster main node HA begin ...")
      print(f"Getting saved CoPilot config from the controller")
      config = api.get_copilot_config(event['copilot_type'])
      print(f"get_copilot_config: {config}")
      # abort restore if unable to get config
      if config == {}:
        print(f"Unable to get saved config. Abort restore")
        return
      # setting possibly new controller IP in saved config
      config['singleCopilot']['copilotConfigFiles']['db.json']['config']['controllerIp'] = event['controller_info']['public_ip']
      # 2. restore saved config on new copilot
      print(f"Restoring config on CoPilot: {config}")
      response = copilot_api.restore_copilot(config)
      print(f"restore_config: {response}")
      print(f"Getting restore_config status")
      copilot_api.wait_copilot_restore_complete(event['copilot_type'])
      print("CoPilot restore end")
    else:
      # clustered copilot data node HA
      print(f"Clustered CoPilot data node HA use case ...")
  
  # Post init or HA actions
  # 1. enable copilot config backup on new copilot instances
  print("Enabling CoPilot config backup to the controller")
  response = copilot_api.enable_copilot_backup()
  print(f"enable_copilot_backup: {response}")
  response = copilot_api.get_copilot_backup_status()
  print(f"get_copilot_backup: {response}")
  # 2. update the controller syslog server, netflow server, and copilot association
  print("Updating controller Syslog server, Netflow server, and CoPilot association")
  # make sure controller sg is open
  api.manage_sg_access(ec2_client, event['controller_info']['sg_id'], True)
  controller_copilot_setup(api, event)
  # close controller sg
  api.manage_sg_access(ec2_client, event['controller_info']['sg_id'], False)

if __name__ == "__main__":
  copilot_event = {
    "region": "",
    "copilot_init": True,
    "copilot_type": "singleNode", # values should be "singleNode" or "fault-tolerant"
    "cluster_ha_main_node": True, # if clustered copilot HA case, set to True if HA for main node
    "copilot_data_node_public_ips": ["",
                                      ""], # cluster data nodes public IPs
    "copilot_data_node_private_ips": ["",
                                      ""], # cluster data nodes private IPs
    "copilot_data_node_regions": ["",
                                      ""], # cluster data nodes regions (should be the same)
    "copilot_data_node_names": ["",
                                      ""], # names to be displayed in copilot cluster info
    "copilot_data_node_usernames": ["",
                                      ""],
    "copilot_data_node_passwords": ["",
                                      ""],
    "copilot_data_node_volumes": ["",
                                  ""], # linux volume names (eg "/dev/sdf") - can be the same
    "copilot_data_node_sg_names": ["",
                                    ""], # cluster data nodes security group names
    "controller_info": {
        "public_ip": "",
        "private_ip": "",
        "username":  "",
        "password": "",
        "sg_id": "", # controller security group ID
        "sg_name": ""  # controller security group name
    },
    "copilot_info": {
        "public_ip": "",
        "private_ip": "",
        "username":  "",
        "password": "",
        "sg_id": "", # (main) copilot security group ID
        "sg_name": ""  # (main) copilot security group name
    }
  }
  print(f"Running CoPilot HA from main(), with event: {copilot_event}")
  handle_copilot_ha(copilot_event)

