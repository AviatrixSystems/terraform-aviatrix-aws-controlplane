import argparse
import boto3
import botocore
import sys


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Stop ECS Tasks")
    parser.add_argument("--cluster", help="Cluster Name")
    parser.add_argument("--region", help="Region")
    args = parser.parse_args()

    client = boto3.client("ecs", region_name=args.region)
    try:
        response = client.list_tasks(cluster=args.cluster)
        print(response)
    except client.exceptions.ClusterNotFoundException:
        print("ECS cluster has already been deleted")
        sys.exit()

    task_arns = response["taskArns"]

    for task in task_arns:
        print("Stopping task:", task)
        client.stop_task(cluster=args.cluster, task=task)
