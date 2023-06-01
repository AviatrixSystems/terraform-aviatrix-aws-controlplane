import sys
from subprocess import call

if len(sys.argv) != 2:
    print("Error wrong parameter number")
    print("Usage: python runterraform.py destroy")
    print("Example: python runterraform.py false")
    sys.exit(1)

destroy = sys.argv[1]
action = "apply"
if destroy.lower() == "true":
    action = "destroy"

cmd = ["terraform", action, "-auto-approve"]

print(cmd)
call(cmd)
