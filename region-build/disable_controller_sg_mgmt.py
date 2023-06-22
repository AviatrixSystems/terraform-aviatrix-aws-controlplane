import argparse
import boto3
import json
import logging
import requests
import time
import traceback


requests.packages.urllib3.disable_warnings()


class AviatrixException(Exception):
    def __init__(self, message="Aviatrix Error Message: ..."):
        super(AviatrixException, self).__init__(message)


def get_password(password, ssm_path, ssm_region):
    if password != "" and password is not None:
        return password
    else:
        try:
            ssm_client = boto3.client("ssm", ssm_region)
            response = ssm_client.get_parameter(Name=ssm_path, WithDecryption=True)
            return response["Parameter"]["Value"]
        except Exception:
            logging.exception("Error fetching from SSM")


def login(
    api_endpoint_url="https://123.123.123.123/v1/api",
    username="admin",
    password="********",
    hide_password=True,
):
    request_method = "POST"
    data = {"action": "login", "username": username, "password": password}
    logging.info("API endpoint url is : %s", api_endpoint_url)
    logging.info("Request method is : %s", request_method)

    # handle if the hide_password is selected
    if hide_password:
        payload_with_hidden_password = dict(data)
        payload_with_hidden_password["password"] = "************"
        logging.info(
            "Request payload: %s",
            str(json.dumps(obj=payload_with_hidden_password, indent=4)),
        )
    else:
        logging.info("Request payload: %s", str(json.dumps(obj=data, indent=4)))

    # send post request to the api endpoint
    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
    )

    api_token = ""
    if not response.json()["return"]:
        if response.json()["reason"] == "Invalid API token":
            api_endpoint_url = api_endpoint_url[:-5] + "2" + api_endpoint_url[-4:]

            api_token_resp = send_aviatrix_api(
                api_endpoint_url=api_endpoint_url,
                request_method="GET",
                payload={"action": "get_api_token"},
            )

            api_token = api_token_resp.json()["results"]["api_token"]
            data["api_token"] = api_token

            response = send_aviatrix_api(
                api_endpoint_url=api_endpoint_url,
                request_method=request_method,
                payload=data,
            )

    return response, api_token


# End def login()


def send_aviatrix_api(
    api_endpoint_url="https://123.123.123.123/v1/api",
    request_method="POST",
    payload=dict(),
    retry_count=5,
    timeout=None,
):
    response = None
    responses = list()
    request_type = request_method.upper()
    response_status_code = -1

    for i in range(retry_count):
        try:
            if request_type == "GET":
                response = requests.get(
                    url=api_endpoint_url, params=payload, verify=False
                )
                response_status_code = response.status_code
            elif request_type == "POST":
                response = requests.post(
                    url=api_endpoint_url, data=payload, verify=False, timeout=timeout
                )
                response_status_code = response.status_code
            else:
                failure_reason = "ERROR : Bad HTTPS request type: " + request_type
                logging.error(failure_reason)
        except requests.exceptions.Timeout as e:
            logging.exception("WARNING: Request timeout...")
            responses.append(str(e))
        except requests.exceptions.ConnectionError as e:
            logging.exception("WARNING: Server is not responding...")
            responses.append(str(e))
        except Exception as e:
            traceback_msg = traceback.format_exc()
            logging.exception("HTTP request failed")
            responses.append(str(traceback_msg))
            # For error message/debugging purposes

        finally:
            if response_status_code == 200:
                return response
            elif response_status_code == 404:
                failure_reason = "ERROR: 404 Not Found"
                logging.error(failure_reason)

            # if the response code is neither 200 nor 404, repeat the precess (retry)
            # the default retry count is 5, the wait for each retry is i
            # i           =  0  1  2  3  4
            # wait time   =     1  2  4  8

            if i + 1 < retry_count:
                logging.info("START: retry")
                logging.info("i == %d", i)
                wait_time_before_retry = pow(2, i)
                logging.info("Wait for: %ds for the next retry", wait_time_before_retry)
                time.sleep(wait_time_before_retry)
                logging.info("ENDED: Wait until retry")
                # continue next iteration
            else:
                failure_reason = (
                    "ERROR: Failed to invoke Aviatrix API. Exceed the max retry times. "
                    + " All responses are listed as follows :  "
                    + str(responses)
                )
                raise AviatrixException(
                    message=failure_reason,
                )
            # END
    return response


# End def send_aviatrix_api()


def verify_aviatrix_api_response_login(response=None):
    # if successfully login
    # response_code == 200
    # api_return_boolean == true
    # response_message = "authorized successfully"

    py_dict = response.json()
    logging.info("Aviatrix API response is %s", str(py_dict))

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


# End def verify_aviatrix_api_response_login()


def disable_controller_sg_mgmt(
    api_endpoint_url="https://123.123.123.123/v1/api", CID="ABCD1234", api_token=""
):
    data = {"action": "disable_controller_security_group_management", "CID": CID}

    if api_token != "":
        data["api_token"] = api_token

    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method="POST",
        payload=data,
        timeout=60,
    )

    return response


def function_handler(event):
    public_ip = event["public_ip"]
    admin_password = event["admin_password"]

    api_endpoint_url = "https://" + public_ip + "/v1/api"

    logging.info("CLEANING UP START: Disable the controller security group management.")

    response, api_token = login(
        api_endpoint_url=api_endpoint_url,
        username="admin",
        password=admin_password,
    )

    verify_aviatrix_api_response_login(response=response)
    CID = response.json()["CID"]

    if api_token != "":
        api_endpoint_url = api_endpoint_url[:-5] + "2" + api_endpoint_url[-4:]

    response = disable_controller_sg_mgmt(
        api_endpoint_url=api_endpoint_url, CID=CID, api_token=api_token
    )

    py_dict = response.json()

    response_code = response.status_code
    if response_code != 200:
        err_msg = (
            "Fail to disable controller security group management. The response code is"
            + response_code
        )
        raise AviatrixException(message=err_msg)

    api_return_boolean = py_dict["return"]
    if api_return_boolean is not True:
        err_msg = (
            "Fail to disable controller security group management. The Response is"
            + str(py_dict)
        )
        raise AviatrixException(
            message=err_msg,
        )

    logging.info(
        "CLEANING UP ENDED: Disabled the controller security group management."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Disable Controller Security Group Management")
    parser.add_argument(
        "--avx_password",
        help="The password if it was specfied directly rather than in SSM",
        nargs="?",
        default="",
    )
    parser.add_argument("--avx_password_ssm_path", help="The SSM path to the password")
    parser.add_argument(
        "--avx_password_ssm_region", help="The region the SSM parameter is in"
    )
    parser.add_argument("--controller_ip")
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s disable-controller-sg-mgmt--- %(message)s",
        level=logging.INFO,
    )

    public_ip = args.controller_ip
    admin_password = get_password(
        args.avx_password, args.avx_password_ssm_path, args.avx_password_ssm_region
    )

    event = {"public_ip": public_ip, "admin_password": admin_password}

    try:
        function_handler(event)
    except Exception as e:
        logging.exception("")
    else:
        logging.info("Controller security group management has been disabled.")
