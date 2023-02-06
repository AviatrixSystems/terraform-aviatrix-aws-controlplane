import boto3
import warnings
import urllib3
import time
import traceback
import requests
import uuid
from typing import Dict, List, Any
import json
warnings.filterwarnings("ignore", category=DeprecationWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAITING_LARGE = 30
WAITING_SMALL = 5
NETFLOW_PORT = 31283
NETFLOW_VER = "9"
NETFLOW_L7_MODE = "disable"
RSYSLOG_PORT = 5000
RSYSLOG_INDEX = "9"
PORT_HTTPS = 443
PROTO_UDP = "UDP"
IPV4_ANY = "0.0.0.0/0"

def revoke_security_group_ingress(
    ec2_client,
    security_group_id: str,
    from_port: int,
    to_port: int,
    protocol: str = "tcp",
    cidr_list: List[str] = [],
) -> None:
    modify_security_group_ingress(ec2_client, "del_rule", security_group_id, from_port, to_port, protocol, cidr_list)

def authorize_security_group_ingress(
    ec2_client,
    security_group_id: str,
    from_port: int,
    to_port: int,
    protocol: str = "tcp",
    cidr_list: List[str] = [],
) -> None:
    modify_security_group_ingress(ec2_client, "add_rule", security_group_id, from_port, to_port, protocol, cidr_list)

def modify_security_group_ingress(
    ec2_client,
    operation: str,
    security_group_id: str,
    from_port: int,
    to_port: int,
    protocol: str = "tcp",
    cidr_list: List[str] = [],
) -> None:
    if operation == "add_rule":
        fn = ec2_client.authorize_security_group_ingress
    elif operation == "del_rule":
        fn = ec2_client.revoke_security_group_ingress
    fn(
        GroupId=security_group_id,
        IpPermissions=[
            {
                "FromPort": from_port,
                "ToPort": to_port,
                "IpProtocol": protocol,
                "IpRanges": [
                    {
                        "CidrIp": cidr,
                        "Description": "Added by copilot ha script"
                    } for cidr in cidr_list
                ]
            }
        ]
    )


class ControllerAPI:
    def __init__(self, controller_ip: str) -> None:
        self._controller_ip: str = controller_ip
        self._cid: str = ""
        self._api_token: str = ""

    def v1(
        self,
        action: str,
        params: Dict[str, Any] = {},
        data: Dict[str, Any] = {},
        headers: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        url = f"https://{self._controller_ip}/v1/api"
        return self._make_api_request("POST", url, action, params=params, data=data, headers=headers)
    
    def v1_backend(
        self,
        action: str,
        params: Dict[str, Any] = {},
        data: Dict[str, Any] = {},
        headers: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        url = f"https://{self._controller_ip}/v1/backend1"
        return self._make_api_request("POST", url, action, params=params, data=data, headers=headers)

    def v2(
        self,
        http_method: str,
        action: str,
        params: Dict[str, Any] = {},
        data: Dict[str, Any] = {},
        headers: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        url = f"https://{self._controller_ip}/v2/api"
        return self._make_api_request(http_method, url, action, params=params, data=data, headers=headers)

    def _make_api_request(
        self,
        http_method: str,
        url: str,
        action: str,
        params: Dict[str, Any] = {},
        data: Dict[str, Any] = {},
        headers: Dict[str, Any] = {},
        retry_max: int = WAITING_SMALL,
    ) -> Dict[str, Any]:
        if http_method == "POST":
            retry_max = WAITING_LARGE
        retry_cnt = retry_max
        while retry_cnt:
            try:
                return self._trigger_api_request(http_method, url, action, params=params, data=data, headers=headers)
            except Exception as err:
                print(f"{action} retry {retry_cnt}/{retry_max}: {err}")
                time.sleep(15)
                retry_cnt -= 1
                if not retry_cnt:
                    raise err
    
    def _trigger_api_request(
        self,
        http_method: str,
        url: str,
        action: str,
        params: Dict[str, Any] = {},
        data: Dict[str, Any] = {},
        headers: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        try:
            resp = {}
            if http_method == "GET":
                params["action"] = action
                params["CID"] = self._cid
                r = requests.get(
                    url=url, params=params, verify=False, timeout=15,
                )
                resp = r.json()
            elif http_method == "POST":
                data["action"] = action
                data["CID"] = self._cid
                r = requests.post(
                    url=url, data=data, headers=headers, verify=False, timeout=15,
                )
                resp = r.json()
            else:
                print(f"Unsupported HTTP method: {http_method}")
            return resp
        except urllib3.exceptions.ReadTimeoutError as err:
            return {"return": False, "reason": "urllib3 read timed out", "error": str(err)}
        except requests.exceptions.ReadTimeout as err:
            return {"return": False, "reason": "requests read timed out", "error": str(err)}

    def get_api_token(self) -> Dict[str, Any]:
        resp = {}
        try:
            resp = self.v2("GET", "get_api_token")
            results = resp.get("results", {})
            self._api_token = results.get("api_token", "")
            print(f"Successfully get API token, token={self._api_token}")
        except Exception as err:
            print(f"Failed to get API token, {err}")
        return resp

    def login(self, username: str, password: str) -> None:
        self.get_api_token()
        resp = self._login(username, password)
        cid = resp.get("CID")
        if cid:
            self._cid = cid
            print(f"Successfully logged in, cid={self._cid}")
        else:
            print(f"Cannot retrieve CID , {resp}")

    def _login(self, username: str, password: str) -> Dict[str, Any]:
        try:
            data = {
                "username": username,
                "password": password,
            }
            headers = {"X-Access-Key": self._api_token}
            return self.v2("POST", "login", data=data, headers=headers)
        except Exception as e:
            return {"return": False, "reason": str(e)}

    def initial_setup(self, subaction: str, target_version: str = "latest") -> Dict[str, Any]:
        try:
            data = {
                "subaction": subaction,
                "target_version": target_version,
            }
            return self.v1("initial_setup", data=data)
        except Exception as e:
            return {"return": False, "reason": str(e)}

    def wait_initial_setup_complete(self) -> Dict[str, Any]:
        for i in range(WAITING_LARGE):
            resp = self.initial_setup("check")
            print(f"Controller initial setup #{i:02d}: {resp}")
            time.sleep(15)
            if resp.get("return"):
                print(f"Controller initial setup successfully: {resp}")
                break

    def cloud_diag_restart(self) -> Dict[str, Any]:
        for i in range(WAITING_SMALL):
            resp = self._cloud_diag_restart()
            if resp.get("return"):
                break
            print(f"Cannot restart Controller #{i:02d}, {resp}")
            time.sleep(15)
    
    def _cloud_diag_restart(self) -> Dict[str, Any]:
        try:
            data = {
                "subaction": "restart",
            }
            return self.v1_backend("cloudxd_diag", data=data)
        except Exception as e:
            return {"return": False, "reason": str(e)}

    def add_admin_email_addr(self, admin_email) -> Dict[str, Any]:
        data = {
            "admin_email": admin_email
        }
        return self.v1("add_admin_email_addr", data=data)
    
    def skip_proxy_config(self) -> Dict[str, Any]:
        return self.v2("POST", "skip_proxy_config")

    def edit_account_user(self, old_password, new_password) -> Dict[str, Any]:
        data = {
            "what": "password",
            "username": "admin",
            "old_password": old_password,
            "new_password": new_password,
        }
        return self.v2("POST", "edit_account_user", data=data)

    def get_copilot_association_status(self) -> Dict[str, Any]:
        # return self.v2("GET", "get_copilot_association_status")
        return self.v1("get_copilot_association_status")

    def get_remote_syslog_logging_status(self) -> Dict[str, Any]:
        # return self.v2("GET", "get_remote_syslog_logging_status")
        return self.v1("get_remote_syslog_logging_status")

    def get_netflow_agent(self) -> Dict[str, Any]:
        # return self.v2("GET", "get_netflow_agent")
        return self.v1("get_netflow_agent")

    def enable_copilot_association(self, copilot_ip: str, public_ip: str) -> Dict[str, Any]:
        data = {
            "copilot_ip": copilot_ip,
            "public_ip": public_ip,
        }
        # return self.v2("POST", "enable_copilot_association", data=data)
        return self.v1("enable_copilot_association", data=data)

    def enable_netflow_agent(self, copilot_ip: str) -> Dict[str, Any]:
        data = {
            "server_ip": copilot_ip,
            "port": NETFLOW_PORT,
            "version": NETFLOW_VER,
            "l7_mode": NETFLOW_L7_MODE,
        }
        # return self.v2("POST", "enable_netflow_agent", data=data)
        return self.v1("enable_netflow_agent", data=data)

    def enable_syslog_configuration(self, copilot_ip: str) -> Dict[str, Any]:
        data = {
            "index": RSYSLOG_INDEX,
            "name": "Aviatrix CoPilot Remote Syslog Profile",
            "server": copilot_ip,
            "port": RSYSLOG_PORT,
            "protocol": PROTO_UDP,
        }
        # return self.v2("POST", "enable_remote_syslog_logging", data=data)
        return self.v1("enable_remote_syslog_logging", data=data)
    
    def pull_copilot_config_from_api(self) -> Dict[str, Any]:
        return self.v2("POST", "get_copilot_data")
    
    def get_copilot_config(self) -> Dict[str, Any]:
        api_response = self.pull_copilot_config_from_api()
        return api_response['results']


class CoPilotAPI:
    def __init__(self, copilot_ip: str, cid: str) -> None:
        self._copilot_ip: str = copilot_ip
        self._cid: str = cid

    def v1(
        self,
        http_method: str,
        endpoint: str,
        params: Dict[str, Any] = {},
        data: Dict[str, Any] = {},
        headers: Dict[str, Any] = {},
        retry_max: int = WAITING_SMALL,
    ) -> Dict[str, Any]:
        if http_method == "POST":
            retry_max = WAITING_LARGE
        retry_cnt = retry_max
        while retry_cnt:
            try:
                return self._trigger_api_request(http_method, endpoint, params=params, data=data, headers=headers)
            except Exception as err:
                print(f"{endpoint} retry {retry_cnt}/{retry_max}: {err}")
                time.sleep(15)
                retry_cnt -= 1
                if not retry_cnt:
                    raise err
    
    def _trigger_api_request(
        self,
        http_method: str,
        endpoint: str,
        params: Dict[str, Any] = {},
        data: Dict[str, Any] = {},
        headers: Dict[str, Any] = {},
    ) -> Dict[str, Any]:
        try:
            if endpoint == "login":
                url = f"https://{self._copilot_ip}/login"
            else:
                url = f"https://{self._copilot_ip}/v1/api/{endpoint}"
            resp = {}
            headers["Content-Type"] = "application/json"
            if not endpoint == "login":
                headers["CID"] = self._cid
            if http_method == "GET":
                r = requests.get(
                    url=url, params=params, headers=headers, verify=False, timeout=15,
                )
                resp = r.json()
            elif http_method == "POST":
                r = requests.post(
                    url=url, data=json.dumps(data), headers=headers, verify=False, timeout=None,
                )
                if endpoint == "login":
                    resp = r.status_code
                else:
                    resp = r.json()
            elif http_method == "PUT":
                r = requests.put(
                    url=url, json=data, headers=headers, verify=False, timeout=15,
                )
                resp = r.json()
            else:
                print(f"Unsupported HTTP method: {http_method}")
            return resp
        except urllib3.exceptions.ReadTimeoutError as err:
            return {"return": False, "reason": "urllib3 read timed out", "error": str(err)}
        except requests.exceptions.ReadTimeout as err:
            return {"return": False, "reason": "requests read timed out", "error": str(err)}
    
    def enable_copilot_backup(self) -> Dict[str, Any]:
        return self.v1("PUT", "configuration/backup", {}, {"enabled": "true"})
  
    def disable_copilot_backup(self) -> Dict[str, Any]:
        return self.v1("PUT", "configuration/backup", {}, {"enabled": "false"})

    def get_copilot_backup_status(self) -> Dict[str, Any]:
        return self.v1("GET", "configuration/backup")

    def get_copilot_init_status(self, type) -> Dict[str, Any]:
        if type == "singleNode":
            return self.v1("GET", "single-node")
        elif type == "clustered":
            return self.v1("GET", "cluster")
        else:
            raise Exception(f"get_copilot_init_status: Unexpected type: {type}")
    
    def set_controller_ip(self, controller_ip, username: str, password: str) -> Dict[str, Any]:
        data = {
            "controllerIp": controller_ip,
            "username": username,
            "password": password
        }
        return self.v1("POST", "login", params={}, data=data)

    def init_copilot_single_node(self, username: str, password: str) -> Dict[str, Any]:
        data = {
            "taskserver": {
                "username": username,
                "password": password,
            }
        }
        return self.v1("POST", "single-node", data=data)
    
    def restore_copilot(self, config):
        return self.v1("POST", "configuration/restore", params={}, data=config)
    
    def get_copilot_restore_status(self):
        return self.v1("GET", "configuration/restore")
    
    def wait_copilot_restore_complete(self, type) -> None:
        self._wait_copilot_api("restore", "complete", type)
        
    def wait_copilot_restore_ready(self, type) -> None:
        self._wait_copilot_api("restore", "ready", type)
        
    def wait_copilot_init_complete(self, type) -> None:
        self._wait_copilot_api("init", "complete", type)
        
    def wait_copilot_init_ready(self, type) -> None:
        self._wait_copilot_api("init", "ready", type)
        
    def _wait_copilot_api(self, api, state, type) -> None:
        for i in range(40):
            if api == "restore":
                resp = self.get_copilot_restore_status()
            elif api == "init":
                resp = self.get_copilot_init_status(type)
            else:
                raise Exception(f"Unexpected API: {api}")
            status = resp.get("status")
            if status == "failed":
                print(f"CoPilot type '{type}' API '{api} status failed, but will recheck: {resp}")
            if state == "ready" and status == "waiting":
                print(f"CoPilot type '{type}' API '{api}' is ready: {resp}")
                break
            if state == "complete" and status == "done":
                print(f"CoPilot type '{type}' API '{api}' completed: {resp}")
                break
            print(f"Status for API '{api}' for CoPilot type '{type}' and state '{state}' #{i:02d}: {resp}")
            time.sleep(15)
        else:
            raise Exception(f"Exceed the limitation of CoPilot type '{type}'  API '{api}' checks")

