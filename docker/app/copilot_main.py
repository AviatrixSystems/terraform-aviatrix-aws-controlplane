import boto3
import time
import single_copilot_lib as single_cplt

def controller_copilot_setup(api, copilot_info):  
  # enable copilot association
  print("Associate Aviatrix CoPilot with Aviatrix Controller")
  api.enable_copilot_association(copilot_info["private_ip"], copilot_info["public_ip"])
  response = api.get_copilot_association_status()
  print(f"get_copilot_association_status: {response}")
  # enable netflow
  print("Enable Netflow Agent configuration on Aviatrix Controller")
  api.enable_netflow_agent(copilot_info["public_ip"])
  # api.enable_netflow_agent(copilot_info["private_ip"])
  response = api.get_netflow_agent()
  print(f"get_netflow_agent: {response}")
  # enable syslog
  print("Enable Remote Syslog configuration on Aviatrix Controller")
  # api.enable_syslog_configuration(copilot_info["private_ip"])
  api.enable_syslog_configuration(copilot_info["public_ip"])
  response = api.get_remote_syslog_logging_status()
  print(f"get_remote_syslog_logging_status: {response}")

def handle_coplot_ha(event):
  
  # Preliminary actions - wait for CoPilot instances to be ready
  print(f"Starting CoPilot HA with copilot_init = '{event['copilot_init']}' and copilot_type = '{event['copilot_type']}'")
  print(f"Waiting for CoPilot API to be ready")
  ec2_client = boto3.client("ec2", region_name=event['region'])
  waiter = ec2_client.get_waiter("instance_status_ok")
  waiter.wait(InstanceIds=event['instance_ids'])
  time.sleep(600)

  # login in to the controller and copilot
  if event['copilot_type'] == "singleNode":
    # Security group adjustment
    # allow 443 from the copilot to the controller
    single_cplt.authorize_security_group_ingress(ec2_client,
                                                 event['security_group_id'],
                                                 443, 443, 'tcp',
                                                 [f"{event['copilot_info']['public_ip']}/32"])
    api = single_cplt.ControllerAPI(controller_ip=event['controller_info']['public_ip'])
    api.login(username=event['controller_info']['username'],
              password=event['controller_info']['password'])
    copilot_api = single_cplt.CoPilotAPI(copilot_ip=event['copilot_info']['public_ip'],
                                         cid=api._cid)
    # set the new copilot to use the controller to verify logins
    print("Set controller IP on CoPilot")
    resp = copilot_api.set_controller_ip(event['controller_info']['public_ip'],
                                         event['copilot_info']['username'],
                                         event['copilot_info']['password'])
    print(f"set_controller_ip: {resp}")

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
  else:
    # copilot HA use case
    if event['copilot_type'] == "singleNode":
      # singleNode copilot HA
      # 1. get saved config from controller
      # 2. restore saved config on new copilot
      print(f"SingleNode CoPilot HA begin ...")
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
  controller_copilot_setup(api, event['copilot_info'])  

  
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
  
  