import json
import boto3

session = boto3.Session()
ssm_client = session.client("ssm", region_name="ap-south-1") # change to appropriate aws region
ec2_client = session.client('ec2', region_name="ap-south-1")

def docker_container(event, context):
    
    print("event: {}".format(event))
    cmd = {"commands": ["docker rm -f $(docker ps -a --format '{{.CreatedAt}}\\t{{.ID}}' | awk -F $'\\t' 'NR==1 { earliest = $1; result = $2; next; } $1 < earliest { earliest = $1; result = $2; } END { print result; }') || true"]}
    instanceId = get_instance_id()

    ssm_client.send_command(DocumentName="AWS-RunShellScript", InstanceIds=[instanceId], Parameters=cmd)
    print("Docker container(s) destroyed!")
    return {
        'statusCode': 200,
        'body': json.dumps("Docker container(s) destroyed!")
    }

# Function to get ec2 instance id of the target instance
def get_instance_id():

    custom_filter = [
        {
            'Name': 'instance-state-name',
            'Values': ['running']
        },
        {
            'Name': 'tag:Name',
            'Values': ["critical_app"]
        }
    ]

    instance_id = ""

    response = ec2_client.describe_instances(Filters=custom_filter)
    print("#Reservations: {}".format(len(response['Reservations'])))
    for item in response['Reservations']:
        print("#Instances: {}".format(len(item['Instances'])))
        for instance in item["Instances"]:
            instance_id = instance['InstanceId']

    print("instance_id: {}".format(instance_id))
    return instance_id
