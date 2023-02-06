import json
import sys
import time
import traceback
import requests
import uuid
from botocore.exceptions import ClientError


class AviatrixException(Exception):
    def __init__(self, message="Aviatrix Error Message: ..."):
        super(AviatrixException, self).__init__(message)


def add_ingress_rules(
        ec2_client,
        private_ip,
        rules,
        sg_name
):
    filters = [{
        'Name': 'private-ip-address',
        'Values': [private_ip],
    }]

    instance = ec2_client.describe_instances(Filters=filters)
    security_groups = instance['Reservations'][0]['Instances'][0]['SecurityGroups']

    security_group_id = ''
    for sg in security_groups:
        if sg_name in sg['GroupName']:
            security_group_id = sg['GroupId']
    if not security_group_id:
        raise AviatrixException(
            message="Could not get the security group ID.",
        )

    try:
        response = ec2_client.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=rules)
    except ClientError:
        print(f'Could not create ingress security group rule.')
        raise
    else:
        return response


def send_aviatrix_api(
        api_endpoint_url="https://123.123.123.123/v1/api",
        request_method="POST",
        payload=dict(),
        headers=dict(),
        retry_count=5,
        sleep_between_retries=0,
        timeout=None,
        files=dict(),
):
    response = None
    responses = list()
    request_type = request_method.upper()
    response_status_code = -1

    for i in range(retry_count):
        try:
            if request_type == "GET":
                response = requests.get(
                    url=api_endpoint_url, params=payload, headers=headers, verify=False
                )
                response_status_code = response.status_code
            elif request_type == "POST":
                response = requests.post(
                    url=api_endpoint_url, data=payload, headers=headers, verify=False, timeout=timeout, files=files
                )
                response_status_code = response.status_code
            else:
                failure_reason = "ERROR : Bad HTTPS request type: " + request_type
                print(failure_reason)
        except requests.exceptions.Timeout as e:
            print("WARNING: Request timeout...")
            responses.append(str(e))
        except requests.exceptions.ConnectionError as e:
            print("WARNING: Server is not responding...")
            responses.append(str(e))
        except Exception as e:
            traceback_msg = traceback.format_exc()
            print("HTTP request failed")
            responses.append(str(traceback_msg))

        finally:
            if response_status_code == 200:
                return response
            elif response_status_code == 404:
                failure_reason = "ERROR: 404 Not Found"
                print(failure_reason)
            else:
                return response

            # if the response code is neither 200 nor 404, repeat the precess (retry)

            if i + 1 < retry_count:
                print(f"START: retry")
                print(f"i == {i}")
                print(f"Wait for: {sleep_between_retries}s for the next retry", sleep_between_retries)
                time.sleep(sleep_between_retries)
                print(f"ENDED: Wait until retry")
                # continue next iteration
            else:
                failure_reason = (
                        "ERROR: Failed to invoke API at " + api_endpoint_url + ". Exceed the max retry times. "
                        + " All responses are listed as follows :  "
                        + str(responses)
                )
                raise AviatrixException(
                    message=failure_reason,
                )

    return response


def login_controller(
        controller_ip,
        username,
        password,
        hide_password=True,
):
    request_method = "POST"
    data = {
        "action": "login",
        "username": username,
        "password": password
    }

    api_endpoint_url = "https://" + controller_ip + "/v1/api"
    print(f"API endpoint url is : {api_endpoint_url}", )

    # handle if the hide_password is selected
    if hide_password:
        payload_with_hidden_password = dict(data)
        payload_with_hidden_password["password"] = "************"
        print(f"Request payload: {json.dumps(obj=payload_with_hidden_password, indent=4)}")
    else:
        print(f"Request payload: {json.dumps(obj=data, indent=4)}")

    # send post request to the api endpoint
    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
        retry_count=12,
        sleep_between_retries=10
    )

    return response


def verify_controller_login_response(response=None):
    # if successfully login
    # response_code == 200
    # api_return_boolean == true
    # response_message = "authorized successfully"

    py_dict = response.json()
    print(f"Aviatrix API response is {str(py_dict)}")

    response_code = response.status_code
    if response_code != 200:
        err_msg = (
                "Fail to login Aviatrix Controller. The response code is" + response_code
        )
        raise AviatrixException(message=err_msg)

    api_return_boolean = py_dict["return"]
    if api_return_boolean is not True:
        err_msg = "Fail to Login Aviatrix Controller. The Response is" + str(py_dict)
        raise AviatrixException(
            message=err_msg,
        )

    api_return_msg = py_dict["results"]
    expected_string = "authorized successfully"
    if (expected_string in api_return_msg) is not True:
        err_msg = "Fail to Login Aviatrix Controller. The Response is" + str(py_dict)
        raise AviatrixException(
            message=err_msg,
        )


def login_copilot(
        controller_ip,
        copilot_ip,
        username,
        password,
        hide_password=True,
):
    request_method = "POST"
    data = {
        "controllerIp": controller_ip,
        "username": username,
        "password": password
    }

    api_endpoint_url = "https://" + copilot_ip + "/login"
    print(f"API endpoint url is : {api_endpoint_url}")

    # handle if the hide_password is selected
    if hide_password:
        payload_with_hidden_password = dict(data)
        payload_with_hidden_password["password"] = "************"
        print(f"Request payload: {json.dumps(obj=payload_with_hidden_password, indent=4)}")
    else:
        print(f"Request payload: {json.dumps(obj=data, indent=4)}")

    # send post request to the api endpoint
    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
        retry_count=12,
        sleep_between_retries=10
    )

    return response


def copilot_login_driver(controller_ip, login_info):
    for copilot_ip, username, password in login_info:
        response = login_copilot(controller_ip, copilot_ip, username, password)
        print(f"Login to copilot {copilot_ip} response status: {response.status_code}")

def init_copilot_cluster(
        controller_username,
        controller_password,
        main_copilot_ip,
        init_info,
        CID,
        hide_password=True
):
    request_method = "POST"
    headers = {
        "content-type": "application/json",
        "cid": CID
    }

    cluster_db = []
    for private_ip, volume, name in init_info:
        cluster = {
            "physicalVolumes": [volume],
            "clusterNodeName": name,
            "clusterNodeEIP": private_ip,
            "clusterNodeInterIp": private_ip,
            "clusterUUID": str(uuid.uuid4())
        }
        cluster_db.append(cluster)

    data = {
        "copilotType": "mainCopilot",
        "mainCopilotIp": main_copilot_ip,
        "clusterDB": cluster_db,
        "taskserver": {
            "username": controller_username,
            "password": controller_password
        }
    }

    api_endpoint_url = "https://" + main_copilot_ip + "/v1/api/cluster"
    print(f"API endpoint url is : {api_endpoint_url}")

    # handle if the hide_password is selected
    if hide_password:
        payload_with_hidden_password = dict(data)
        payload_with_hidden_password["taskserver"]["password"] = "************"
        print(f"Request payload: {json.dumps(obj=payload_with_hidden_password, indent=4)}")
        data["taskserver"]["password"] = controller_password
    else:
        print(f"Request payload: {str(json.dumps(obj=data, indent=4))}")

    # send post request to the api endpoint
    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=json.dumps(data),
        headers=headers
    )

    return response


def get_copilot_init_status(
        main_copilot_ip,
        CID,
):
    request_method = "GET"
    headers = {
        "content-type": "application/json",
        "cid": CID
    }

    api_endpoint_url = "https://" + main_copilot_ip + "/v1/api/cluster"
    print(f"API endpoint url is : {api_endpoint_url}")

    # send get request to the api endpoint
    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        headers=headers,
    )

    return response


def function_handler(event):
    # aws_access_key = event["aws_access_key"]
    # aws_secret_access_key = event["aws_secret_access_key"]
    
    ec2_client = event["ec2_client"]

    controller_public_ip = event["controller_public_ip"]
    controller_private_ip = event["controller_private_ip"]
    controller_region = event["controller_region"]
    controller_username = event["controller_username"]
    controller_password = event["controller_password"]

    main_copilot_public_ip = event["main_copilot_public_ip"]
    main_copilot_private_ip = event["main_copilot_private_ip"]
    main_copilot_region = event["main_copilot_region"]
    main_copilot_username = event["main_copilot_username"]
    main_copilot_password = event["main_copilot_password"]

    node_copilot_public_ips = event["node_copilot_public_ips"]
    node_copilot_private_ips = event["node_copilot_private_ips"]
    node_copilot_regions = event["node_copilot_regions"]
    node_copilot_usernames = event["node_copilot_usernames"]
    node_copilot_passwords = event["node_copilot_passwords"]
    node_copilot_data_volumes = event["node_copilot_data_volumes"]
    node_copilot_names = event["node_copilot_names"]

    private_mode = event["private_mode"]

    controller_sg_name = event["controller_sg_name"]
    main_copilot_sg_name = event["main_copilot_sg_name"]
    node_copilot_sg_names = event["node_copilot_sg_names"]

    controller_login_ip = controller_private_ip if private_mode else controller_public_ip
    main_copilot_login_ip = main_copilot_private_ip if private_mode else main_copilot_public_ip

    login_info = zip([main_copilot_private_ip] + node_copilot_private_ips,
                     [main_copilot_username] + node_copilot_usernames,
                     [main_copilot_password] + node_copilot_passwords) if private_mode else \
        zip([main_copilot_public_ip] + node_copilot_public_ips,
            [main_copilot_username] + node_copilot_usernames,
            [main_copilot_password] + node_copilot_passwords)

    init_info = zip(node_copilot_private_ips, node_copilot_data_volumes, node_copilot_names)

    all_copilot_public_ips = [main_copilot_public_ip] + node_copilot_public_ips
    all_copilot_private_ips = [main_copilot_private_ip] + node_copilot_private_ips
    all_copilot_regions = [main_copilot_region] + node_copilot_regions
    all_copilot_sg_names = [main_copilot_sg_name] + node_copilot_sg_names

    ###########################################################
    # Step 1: Sleep 10 min for copilot instances to get ready #
    ###########################################################
    print(f"STEP 1 START: Sleep 10 seconds for copilot instances to get ready.")

    time.sleep(10)

    print(f"STEP 1 ENDED: Slept 10 seconds.")
    
    ###########################################################################
    # Step 2: Modify the security groups for controller and copilot instances #
    ###########################################################################
    print(f"STEP 2 START: Modify the security groups for controller and copilot instances.")

    # modify controller security rule
    controller_rules = []

    if private_mode:
        for ip in all_copilot_private_ips:
            controller_rules.append(
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{
                        "CidrIp": ip + "/32"
                    }]
                }
            )

        add_ingress_rules(
            ec2_client=ec2_client,
            private_ip=controller_private_ip,
            rules=controller_rules,
            sg_name=controller_sg_name
        )
    else:
        for ip in all_copilot_public_ips:
            controller_rules.append(
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{
                        "CidrIp": ip + "/32"
                    }]
                }
            )

        add_ingress_rules(
            ec2_client=ec2_client,
            private_ip=controller_private_ip,
            rules=controller_rules,
            sg_name=controller_sg_name
        )
    # print(fcontroller_rules)

    # modify copilot security rule
    copilot_rules = []

    if private_mode:
        for ip in all_copilot_private_ips:
            copilot_rules.extend(
                [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{
                            "CidrIp": ip + "/32"
                        }]
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 9200,
                        "ToPort": 9200,
                        "IpRanges": [{
                            "CidrIp": ip + "/32"
                        }]
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 9300,
                        "ToPort": 9300,
                        "IpRanges": [{
                            "CidrIp": ip + "/32"
                        }]
                    }
                ]
            )
        for i in range(len(all_copilot_private_ips)):
            add_ingress_rules(
                ec2_client=ec2_client,
                private_ip=all_copilot_private_ips[i],
                rules=copilot_rules,
                sg_name=all_copilot_sg_names[i]
            )
    else:
        for ip in all_copilot_public_ips:
            copilot_rules.extend(
                [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{
                            "CidrIp": ip + "/32"
                        }]
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 9200,
                        "ToPort": 9200,
                        "IpRanges": [{
                            "CidrIp": ip + "/32"
                        }]
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 9300,
                        "ToPort": 9300,
                        "IpRanges": [{
                            "CidrIp": ip + "/32"
                        }]
                    }
                ]
            )

        for ip in all_copilot_private_ips:
            copilot_rules.extend(
                [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{
                            "CidrIp": ip + "/32"
                        }]
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 9200,
                        "ToPort": 9200,
                        "IpRanges": [{
                            "CidrIp": ip + "/32"
                        }]
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 9300,
                        "ToPort": 9300,
                        "IpRanges": [{
                            "CidrIp": ip + "/32"
                        }]
                    }
                ]
            )
        for i in range(len(all_copilot_public_ips)):
            add_ingress_rules(
                ec2_client=ec2_client,
                private_ip=all_copilot_private_ips[i],
                rules=copilot_rules,
                sg_name=all_copilot_sg_names[i]
            )

    # print(fcopilot_rules)

    print(f"STEP 2 ENDED: Modified the security groups for controller and copilot instances.")

    ###################################
    # Step 3: Try to login controller #
    ###################################
    print(f"STEP 3 START: Login controller.")

    response = login_controller(
        controller_ip=controller_login_ip,
        username=controller_username,
        password=controller_password
    )

    verify_controller_login_response(response=response)

    print(f"STEP 3 ENDED: Logged into controller.")

    #################################################################################
    # Step 4: Try to login main copilot and cluster nodes. Retry every 10s for 2min #
    #################################################################################
    print(f"STEP 4 START: Try to login main copilot and cluster nodes. Retry every 10s for 2min.")

    copilot_login_driver(controller_ip=controller_login_ip, login_info=login_info)

    print(f"STEP 4 ENDED: Logged into main copilot and cluster nodes.")

    #######################################
    # Step 5: Login controller to get CID #
    #######################################
    print(f"STEP 5 START: Login controller to get CID.")

    response = login_controller(
        controller_ip=controller_login_ip,
        username=controller_username,
        password=controller_password
    )

    verify_controller_login_response(response=response)
    CID = response.json()["CID"]

    print(f"STEP 5 ENDED: Logged into controller and got CID. #{CID}")

    ##################################################
    # Step 6: Call API to initialize copilot cluster #
    ##################################################
    print(f"STEP 6 START: Call API to initialize copilot cluster.")

    response = init_copilot_cluster(
        controller_username=controller_username,
        controller_password=controller_password,
        main_copilot_ip=main_copilot_login_ip,
        init_info=init_info,
        CID=CID
    )

    if response.status_code != 200:
        print(f"Exception response: {response.json()}")
        raise AviatrixException(message="Initialization API call failed")

    print(f"STEP 6 ENDED: Called API to initialize copilot cluster.")

    #######################################
    # Step 7: Check initialization status #
    #######################################
    print(f"STEP 7 START: Check initialization status.")

    retry_count = 30
    sleep_between_retries = 30

    for i in range(retry_count):
        response = get_copilot_init_status(
            main_copilot_ip=main_copilot_login_ip,
            CID=CID
        )

        py_dict = response.json()
        api_return_msg = py_dict.get("status")
        print(py_dict.get("message"))

        if api_return_msg == "failed":
            raise AviatrixException(message="Initialization failed.")
        elif api_return_msg == "done":
            return

        if i + 1 < retry_count:
            print(f"START: retry")
            print(f"i == {i}")
            print(f"Wait for: {sleep_between_retries}s for the next retry")
            time.sleep(sleep_between_retries)
            print(f"ENDED: Wait until retry")
            # continue next iteration
        else:
            raise AviatrixException(
                message="Exceed the max retry times. Initialization still not done.",
            )

    print(f"STEP 7 ENDED: Initialization status check is done.")


if __name__ == '__main__':
    i = 1
    aws_access_key = sys.argv[i]
    i += 1
    aws_secret_access_key = sys.argv[i]
    i += 1
    controller_public_ip = sys.argv[i]
    i += 1
    controller_private_ip = sys.argv[i]
    i += 1
    controller_region = sys.argv[i]
    i += 1
    controller_username = sys.argv[i]
    i += 1
    controller_password = sys.argv[i]
    i += 1
    main_copilot_public_ip = sys.argv[i]
    i += 1
    main_copilot_private_ip = sys.argv[i]
    i += 1
    main_copilot_region = sys.argv[i]
    i += 1
    main_copilot_username = sys.argv[i]
    i += 1
    main_copilot_password = sys.argv[i]
    i += 1
    node_copilot_public_ips = sys.argv[i].split(",")
    i += 1
    node_copilot_private_ips = sys.argv[i].split(",")
    i += 1
    node_copilot_regions = sys.argv[i].split(",")
    i += 1
    node_copilot_usernames = sys.argv[i].split(",")
    i += 1
    node_copilot_passwords = sys.argv[i].split(",")
    i += 1
    node_copilot_data_volumes = sys.argv[i].split(",")
    i += 1
    node_copilot_names = sys.argv[i].split(",")
    i += 1
    private_mode = sys.argv[i]
    i += 1
    controller_sg_name = sys.argv[i]
    i += 1
    main_copilot_sg_name = sys.argv[i]
    i += 1
    node_copilot_sg_names = sys.argv[i].split(",")

    event = {
        "aws_access_key": aws_access_key,
        "aws_secret_access_key": aws_secret_access_key,
        "controller_public_ip": controller_public_ip,
        "controller_private_ip": controller_private_ip,
        "controller_region": controller_region,
        "controller_username": controller_username,
        "controller_password": controller_password,
        "main_copilot_public_ip": main_copilot_public_ip,
        "main_copilot_private_ip": main_copilot_private_ip,
        "main_copilot_region": main_copilot_region,
        "main_copilot_username": main_copilot_username,
        "main_copilot_password": main_copilot_password,
        "node_copilot_public_ips": node_copilot_public_ips,
        "node_copilot_private_ips": node_copilot_private_ips,
        "node_copilot_regions": node_copilot_regions,
        "node_copilot_usernames": node_copilot_usernames,
        "node_copilot_passwords": node_copilot_passwords,
        "node_copilot_data_volumes": node_copilot_data_volumes,
        "node_copilot_names": node_copilot_names,
        "private_mode": True if private_mode == "true" else False,
        "controller_sg_name": controller_sg_name,
        "main_copilot_sg_name": main_copilot_sg_name,
        "node_copilot_sg_names": node_copilot_sg_names
    }

    try:
        function_handler(event)
    except Exception as e:
        print("Ran into the following issue:")
        print(e)
    else:
        print(f"Aviatrix Copilot Cluster has been initialized successfully.")
