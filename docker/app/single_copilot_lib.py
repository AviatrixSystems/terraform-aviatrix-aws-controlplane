import boto3
import botocore
import warnings
import urllib3
import time
import traceback
import requests
from typing import Dict, List, Any
import json
import datetime
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

    def retry_login(self, username: str, password: str) -> bool:
        attempts = 0
        retries = 10
        delay = 60
        login_success = False
        while attempts <= retries:
            print(f"Retrying login attempt {attempts} / {retries}")
            self.login(username, password)
            if self._cid:
                print(f"Retrieved CID. Login successful: {self._cid}")
                login_success = True
                break
            else:
                print(f"Unable to retrieve CID. Retrying login after {delay} seconds")
                time.sleep(delay)
            attempts += 1
        time.sleep(delay)
        return login_success

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

    def add_account_user(self, user_info: Dict) -> Dict[str, Any]:
        try:
            data = {
                "username": user_info["username"],
                "password": user_info["password"],
                "email": user_info["email"],
                "groups": user_info["user_groups"]
            }
            print(f"Adding user: {data}")
            return self.v1(action="add_account_user", data=data)
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

    def get_copilot_sg_status(self) -> Dict[str, Any]:
        return self.v2("GET", "get_copilot_sg")

    def wait_and_get_copilot_sg_status(self) -> Dict[str, Any]:
        time.sleep(15)
        return self.get_copilot_sg_status()

    def enable_copilot_association(self, copilot_ip: str, public_ip: str) -> Dict[str, Any]:
        data = {
            "copilot_ip": copilot_ip,
            "public_ip": public_ip,
        }
        # return self.v2("POST", "enable_copilot_association", data=data)
        return self.v1("enable_copilot_association", data=data)

    def enable_copilot_sg(
        self,
        account_name: str,
        cloud_type: str,
        region: str,
        vpc_id: str,
        instance_id: str
    ) -> Dict[str, Any]:
        data = {
            "account_name": account_name,
            "cloud_type": cloud_type,
            "region": region,
            "vpc_id": vpc_id,
            "instance_id": instance_id,
        }
        return self.v2("POST", "enable_copilot_sg", data=data)

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
    
    def get_copilot_config(self, copilot_type) -> Dict[str, Any]:
        api_response = self.v2("POST", "get_copilot_data")
        return api_response.get('results', {})

    def retry_get_copilot_config(self, copilot_type) -> bool:
        attempts = 0
        retries = 10
        delay = 60
        copilot_config = {}
        while attempts <= retries:
            print(f"Retrying getting copilot config - attempt {attempts} / {retries}")
            try:
                copilot_config = self.get_copilot_config(copilot_type)
            except Exception as err:
                print(f"Error getting copilot config: {err}")
            if copilot_config == {}:
                print(f"Unable to get copilot config: {copilot_config}. Retrying attempt after {delay} seconds")
                time.sleep(delay)
                attempts += 1
            else:
                print(f"Retrieved copilot config successfully: {copilot_config}")
                break
        time.sleep(delay)
        return copilot_config


class CoPilotAPI:
    def __init__(self, copilot_ip: str, cid: str) -> None:
        self._copilot_ip: str = copilot_ip
        self._cid: str = cid
        self._session = requests.Session()

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
                url = f"https://{self._copilot_ip}/api/login"
            elif endpoint == "updateStatus":
                url = f"https://{self._copilot_ip}/api/info/updateStatus"
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
        if type == "simple":
            return self.v1("GET", "single-node")
        elif type == "fault-tolerant":
            return self.v1("GET", "cluster")
        else:
            raise Exception(f"get_copilot_init_status: Unexpected type: {type}")
    
    def retry_set_controller_ip(self, controller_ip, username: str, password: str) -> bool:
        attempts = 0
        retries = 10
        delay = 60
        set_ip = False
        while attempts <= retries:
            print(f"Retrying setting controller IP on copilot attempt #{attempts} / {retries}")
            resp = self.set_controller_ip(controller_ip=controller_ip, username=username, password=password)
            if str(resp) == "200":
                print(f"Successfully set controller IP")
                set_ip = True
                break
            else:
                print(f"Unable to set controller IP. Retrying after {delay} seconds")
                time.sleep(delay)
            attempts += 1
        time.sleep(delay)
        return set_ip
    
    def set_controller_ip(self, controller_ip, username: str, password: str) -> Dict[str, Any]:
        data = {
            "controllerIp": controller_ip,
            "username": username,
            "password": password
        }
        return self.v1("POST", "login", params={}, data=data)

    def init_copilot_single_node(self, init_config) -> Dict[str, Any]:
        data = {
            "taskserver": init_config
        }
        return self.v1("POST", "single-node", data=data)
    
    def restore_copilot(self, config):
        return self.v1("POST", "configuration/restore", params={}, data=config)
    
    def get_copilot_restore_status(self):
        return self.v1("GET", "configuration/restore")
    
    def wait_copilot_restore_complete(self, cop_type, config) -> None:
        self._wait_copilot_api("restore", "complete", cop_type, config)
        
    def wait_copilot_restore_ready(self, cop_type) -> None:
        self._wait_copilot_api("restore", "ready", cop_type)
        
    def wait_copilot_init_complete(self, cop_type, config) -> None:
        self._wait_copilot_api("init", "complete", cop_type, config)
        
    def wait_copilot_init_ready(self, cop_type) -> None:
        self._wait_copilot_api("init", "ready", cop_type)
        
    def _wait_copilot_api(self, api, state, cop_type, config={}) -> None:
        attempts = 0
        retries = 10
        delay = 60
        api_response = False
        while attempts <= retries:
            print(f"Retrying api {api} for copilot type {cop_type} and state {state} attempt: {attempts} / {retries}")
            if api == "restore":
                resp = self.get_copilot_restore_status()
            elif api == "init":
                resp = self.get_copilot_init_status(cop_type)
            else:
                break
            resp_status = resp.get("status")
            print(f"Status for API '{api}' for CoPilot type '{cop_type}' and state '{state}': {resp}")
            if resp_status == "failed" and attempts < 2 and state == "complete" and config:
                print(f"Copilot {api} attempt {attempts} failed. Will try again in 10 mins with config: {config}")
                time.sleep(600)
                if api == "restore":
                    self.restore_copilot(config)
                elif api == "init" and cop_type == "simple":
                    self.init_copilot_single_node(config)
            elif (state == "ready" and resp_status == "waiting") or (state == "complete" and resp_status == "done"):
                print(f"CoPilot type '{cop_type}' API '{api}' is ready: {resp}")
                api_response = True
                break
            attempts += 1
            print(f"Retrying api check attempt {attempts + 1} in {delay} seconds")
            time.sleep(delay)
        return api_response

    def _get_copilot_upgrade_status(self) -> Dict[str, Any]:
        return self.v1("GET", "updateStatus")

    def retry_upgrade_check(self,) -> bool:
        attempts = 0
        retries = 10
        delay = 60
        upgrade_done = False
        while attempts <= retries:
            print(f"Retrying upgrade check attempt: {attempts} / {retries}")
            try:
                resp = self._get_copilot_upgrade_status()
                status = resp.get("status")
                if status == "finished":
                    print(f"CoPilot upgrade completed: {resp}")
                    upgrade_done = True
                    break
                else:
                    print(f"Upgrade Status is not finished: {resp}")
            except Exception as err:
                print(f"Checking upgrade status attempt err: {err}")
            attempts += 1
            print(f"Retrying upgrade check attempt {attempts + 1} in {delay} seconds")
            time.sleep(delay)
        time.sleep(delay)
        return upgrade_done

    def session_login(self, username: str, password: str) -> bool:
        try:
            return self._session.post(f"https://{self._copilot_ip}/api/login",
                                            data={'username': username, 'password': password},
                                            verify=False)
        except Exception as err:
            raise (f"Error logging in via session: {str(err)}")

    def _make_session_request(self, method: str, endpoint: str, request_data={}):
        request_url = f"https://{self._copilot_ip}"
        try:
            if method == "get":
                resp = self._session.get(f"{request_url}{endpoint}", verify=False)
            elif method == "delete":
                resp = self._session.delete(f"{request_url}{endpoint}", verify=False)
            elif method == "post":
                resp = self._session.post(f"{request_url}{endpoint}", data=request_data, verify=False)
            else:
                resp = f"Unsupported method: {method}"
            return resp
        except Exception as err:
            raise (f"Error making a '{method}' request to '{endpoint}' in the session: {str(err)}")

    def set_data_backup_policy(self, policy_details) -> bool:
        backup_policy = {
            "csp": "Amazon Web Services",
            "accessAccount": policy_details['access_account'],
            "S3": policy_details['bucket_name'],
            "backupRetained": policy_details.get("backup_retained", 30),
            "time": policy_details.get("backup_time", datetime.datetime.now().isoformat()),
            "frequencyRepeat": policy_details.get("frequency_repeat", "Weekly"),
            "frequencyMonth": policy_details.get("frequency_month", "January"),
            "frequencyDay": policy_details.get("frequency_day", "Sunday"),
            "frequencyDate": policy_details.get("frequency_date", "1"),
            "minutes": policy_details.get("frequency_minutes", 0),
            "hours": policy_details.get("frequency_hours", 1)
        }
        return self._make_session_request("post", "/api/backup/policy", backup_policy)

    def create_repo(self, bucket_name) -> bool:
        repo_policy = {
            "backupCloudProvider": "Amazon Web Services",
            "backupExternalStorage": bucket_name
        }
        return self._make_session_request("post", "/api/backup/repo", repo_policy)
