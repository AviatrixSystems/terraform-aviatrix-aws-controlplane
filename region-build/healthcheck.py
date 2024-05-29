import traceback
from datetime import datetime


class AvxError(Exception):
    """Error class for Aviatrix exceptions"""


def lambda_handler(event, context):
    """Entry point of the lambda script"""

    print("START Time:", datetime.now())

    try:
        _lambda_handler(event, context)
    except AvxError as err:
        print("Operation failed due to: " + str(err))
    except Exception as err:
        print(str(traceback.format_exc()))
        print("Lambda function failed due to " + str(err))


def _lambda_handler(event, context):
    """Entry point of the lambda script without exception handling"""

    print(f"Event: {event}")
    print(f"Context: {context}")
