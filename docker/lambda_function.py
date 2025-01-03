import json
import boto3
from botocore.exceptions import ClientError

codebuild = boto3.client("codebuild")


def lambda_handler(event, context):
    print("Received event:", json.dumps(event, indent=2))

    project_name = "Aviatrix_HA"  # Make sure this matches your CodeBuild project name

    try:
        response = codebuild.start_build(projectName=project_name)
        print("Build started successfully:", response)
        return {"statusCode": 200, "body": json.dumps("Build started")}
    except ClientError as error:
        print("Error starting build:", error)
        return {"statusCode": 500, "body": json.dumps("Error starting build")}
