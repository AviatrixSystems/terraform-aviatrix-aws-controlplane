import sys
import subprocess
import boto3
import requests
import json

def cfn_signal_response(success_resp: bool = True):
    signal_resp = {
        'Status': 'SUCCESS' if success_resp else 'FAILURE',
        'Reason': 'Configuration Complete' if success_resp else 'Configuration Failed',
        'UniqueId': 'ID1234' if success_resp else 'ID5678',
        'Data': 'Terraform apply complete' if success_resp else 'Terraform apply failed'
    }
    return signal_resp

def send_cfn_signal(cfn_url: str, success_signal: bool = True):
    print(f"send_cfn_signal signal URL: {cfn_url}")
    cfn_params = cfn_signal_response(success_signal)
    headers = {"Content-Type": "application/json"}
    try:
        cfn_resp = requests.get(url=cfn_url, params=cfn_params, headers=headers)
        print(f"CFN Signal response: {cfn_resp.status_code}")
    except Exception as err:
        print(f"Error sending signal to CFN: {str(err)}")

def get_terraform_output():
    command = "terraform output -json"
    try:
        output = subprocess.check_output(command, shell=True)
        output = output.decode('utf-8')  # Decode the byte string to UTF-8
        output_json = json.loads(output) # Parse the output as JSON
        return output_json
    except subprocess.CalledProcessError as e:
        print(f"Failed to run 'terraform output'. Error: {e}")

def save_ssm_parameter(parameter_name, parameter_value, parameter_type='String', description=''):
    ssm_client = boto3.client('ssm')
    response = ssm_client.put_parameter(
        Name=parameter_name,
        Value=parameter_value,
        Type=parameter_type,
        Description=description,
        Overwrite=True
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        print(f"SSM parameter '{parameter_name}' saved successfully.")
    else:
        print(f"Failed to save SSM parameter '{parameter_name}'.")

def save_tf_outputs():
    tf_output = get_terraform_output()
    print(f"tf_output: {tf_output}")
    for op_key in tf_output.keys():
        if tf_output[op_key]['value'] == '':
            print(f"skipping output {op_key} with empty value: {tf_output[op_key]['value']}")
        else:
            print(f"saving output {op_key} with value {tf_output[op_key]['value']}")
            save_ssm_parameter(f"/aviatrix/controller/{op_key}", tf_output[op_key]['value'])

def main():
    if len(sys.argv) != 3:
        print("Error wrong parameter number")
        print("Usage: python runterraform.py destroy cloud_formation_url")
        print("Example: python runterraform.py false")
        sys.exit(1)

    try:
        destroy = sys.argv[1]
        cfn_url = sys.argv[2]
        action = "apply"
        if destroy.lower() == "true":
            action = "destroy"

        cmd = ["terraform", action, "-auto-approve"]
        print(cmd)
        subprocess.call(cmd)
        if action == 'apply':
            save_tf_outputs()
            send_cfn_signal(cfn_url, True)
    except Exception as err:
        print(f"Error {str(err)}")
        cmd = ["terraform", "destroy", "-auto-approve"]
        print(f"Running Terraform Destroy: {cmd}")
        subprocess.call(cmd)
        send_cfn_signal(cfn_url, False)
        raise err

main()
