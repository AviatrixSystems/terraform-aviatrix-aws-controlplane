import boto3
import time
import traceback
import single_copilot_lib as single_cplt
import cluster_copilot_lib as cluster_cplt

def controller_copilot_setup(api, copilot_priv_ip, copilot_public_ip):
  # enable copilot association
  print("Associate Aviatrix CoPilot with Aviatrix Controller")
  api.enable_copilot_association(copilot_priv_ip, copilot_public_ip)
  response = api.get_copilot_association_status()
  print(f"get_copilot_association_status: {response}")
  # enable netflow
  print("Enable Netflow Agent configuration on Aviatrix Controller")
  api.enable_netflow_agent(copilot_public_ip)
  # api.enable_netflow_agent(copilot_info["private_ip"])
  response = api.get_netflow_agent()
  print(f"get_netflow_agent: {response}")
  # enable syslog
  print("Enable Remote Syslog configuration on Aviatrix Controller")
  # api.enable_syslog_configuration(copilot_info["private_ip"])
  api.enable_syslog_configuration(copilot_public_ip)
  response = api.get_remote_syslog_logging_status()
  print(f"get_remote_syslog_logging_status: {response}")

def handle_coplot_ha(event):
  
  # Preliminary actions - wait for CoPilot instances to be ready
  print(f"Starting CoPilot HA with copilot_init = '{event['copilot_init']}' and copilot_type = '{event['copilot_type']}'")
  ec2_client = boto3.client("ec2", region_name=event['region'])
  print("sleeping for 900 seconds")
  time.sleep(900)

  # Security group adjustment
  if event['copilot_type'] == "singleNode":
    print("Adding CoPilot IP to Controller SG")
    try:
      single_cplt.authorize_security_group_ingress(ec2_client,
                                                  event['controller_info']['sg_id'],
                                                  443, 443, 'tcp',
                                                  [f"{event['copilot_info']['public_ip']}/32"])
    except Exception as err:  # pylint: disable=broad-except
      print(str(traceback.format_exc()))
      print("Adding CoPilot IP to Controller SG failed due to " + str(err))
    try:
      print("Adding Controller IP to CoPilot SG")
      single_cplt.authorize_security_group_ingress(ec2_client,
                                                  event['copilot_info']['sg_id'],
                                                  443, 443, 'tcp',
                                                  [f"{event['controller_info']['public_ip']}/32"])
    except Exception as err:  # pylint: disable=broad-except
      print(str(traceback.format_exc()))
      print("Adding Controller IP to CoPilot SG failed due to " + str(err))
  elif event['copilot_type'] == "clustered":
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
    api.add_account_user(event['copilot_info']['username'],
                         event['copilot_info']['password'],
                         event['copilot_info']['email'],
                         event['copilot_info']['groups'])
    print("sleep for 20 seconds after adding user")
    time.sleep(20)
  # login with copilot user
  api.retry_login(username=event['copilot_info']['username'], password=event['copilot_info']['password'])
  copilot_api = single_cplt.CoPilotAPI(copilot_ip=event['copilot_info']['public_ip'], cid=api._cid)
  # set the new copilot to use the controller to verify logins
  print("Set controller IP on CoPilot")
  resp = copilot_api.retry_set_controller_ip(event['controller_info']['public_ip'],
                                             event['copilot_info']['username'],
                                             event['copilot_info']['password'])
  print(f"set_controller_ip: {resp}")

  # make sure controller sg is open
  api.manage_sg_access(ec2_client, event['controller_info']['sg_id'], True)
  if event['copilot_init']:
    # copilot init use case - not HA
    if event['copilot_type'] == "singleNode":
      # singleNode copilot init
      print("SingleNode CoPilot Initialization begin ...")
      response = copilot_api.init_copilot_single_node(event['copilot_info']['username'],
                                                      event['copilot_info']['password'])
      print(f"singlenode_copilot_init: {response}")
      copilot_api.wait_copilot_init_complete(event['copilot_type'])
    else:
      # clustered copilot init
      print("Clustered CoPilot Initialization begin ...")
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
        "main_copilot_username": event['copilot_info']['username'],
        "main_copilot_password": event['copilot_info']['password'],
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
      # 2. restore saved config on new copilot
      print(f"Restoring config on CoPilot")
      response = copilot_api.restore_copilot(config)
      print(f"restore_config: {response}")
      print(f"Getting restore_config status")
      copilot_api.wait_copilot_restore_complete(event['copilot_type'])
      print("CoPilot restore end")
    else:
      # clustered copilot HA - either main node or data node
      if event['cluster_ha_main_node']:
        # clustered copilot main node HA
        print(f"Clustered CoPilot main node HA begin ...")
      else:
        # clustered copilot data node HA
        print(f"Clustered CoPilot data node HA begin ...")
  
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
  controller_copilot_setup(api, event['copilot_info']['private_ip'], event['copilot_info']['public_ip'])
  # close controller sg
  api.manage_sg_access(ec2_client, event['controller_info']['sg_id'], False)

if __name__ == "__main__":
  copilot_event = {
    "region": "",
    "copilot_init": True,
    "copilot_type": "singleNode", # values should be "singleNode" or "clustered"
    "instance_ids": ["",
                      ""], # list of instances that should be "instance_status_ok"
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
  handle_coplot_ha(copilot_event)

