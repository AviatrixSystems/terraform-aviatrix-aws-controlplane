import argparse
import boto3
import botocore
import time
import sys


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Security groups from VPC")
    parser.add_argument(
        "--delay", help="Delay in seconds before deleting security groups"
    )
    parser.add_argument("--delete_cft", help="CloudFormation stack to delete")
    parser.add_argument("--region", help="Region")
    parser.add_argument("--vpc", help="VPC ID")
    args = parser.parse_args()

    # Insert a short sleep so we don't get an error trying to delete the SGs
    # created by Terraform since they are being destroyed at the same time
    time.sleep(10)

    if args.delete_cft:
        cf_client = boto3.client("cloudformation", region_name=args.region)
        try:
            print("Deleting CloudFormation stack %s" % args.delete_cft)
            response = cf_client.delete_stack(StackName=args.delete_cft)
        except botocore.exceptions.ClientError as e:
            print("Unable to delete CloudFormation statck %s" % args.delete_cft)
            print(e)

    if args.delay:
        time.sleep(int(args.delay))

    client = boto3.client("ec2", region_name=args.region)

    try:
        response = client.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [args.vpc]}]
        )
    except botocore.exceptions.ClientError as e:
        print("VPC %s not found in region %s" % (args.vpc, args.region))
        sys.exit()

    sg_list = [sg["GroupId"] for sg in response["SecurityGroups"]]
    print("Security groups in %s: %s" % (args.vpc, sg_list))

    for sg in sg_list:
        try:
            print("Deleting security group", sg)
            client.delete_security_group(GroupId=sg)
        # We'll get an error deleting the default SG so continue on to the next
        except botocore.exceptions.ClientError as e:
            pass
