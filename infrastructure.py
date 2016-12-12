import boto3
import argparse

from ecs import create_ecs_cluster, create_ecs_ec2, create_ecs_task
from security_group import create_security_groups
from utilities import read_settings_file

parser = argparse.ArgumentParser()
parser.add_argument("settings_file")
args = parser.parse_args()

settings = read_settings_file(args.settings_file)
steps = read_settings_file("steps")

vpc_id = settings["VPC_ID"]

ec2 = boto3.resource('ec2')
vpc = ec2.Vpc(vpc_id)
ecs_client = boto3.client('ecs')

ENVIRONMENT = "DEV"

stack_name = settings["STACK_NAME"] + "-" + ENVIRONMENT

ecs_cluster_name = settings["STACK_NAME"] + "-" + ENVIRONMENT

userdata_string = "#!/bin/bash\necho ECS_CLUSTER=" + ecs_cluster_name + " >> /etc/ecs/ecs.config"

if steps["CREATE_SECURITY_GROUP"] == "True":
    create_security_groups(stack_name, vpc, settings)

if steps["CREATE_CLUSTER"] == "True":
    create_ecs_cluster(ecs_client, ecs_cluster_name)

if steps["CREATE_ECS_EC2"] == "True":
    create_ecs_ec2(stack_name, ecs_cluster_name, vpc, ec2, userdata_string, settings, ENVIRONMENT)

if steps["CREATE_TASK"] == "True":
    ecs_task_family = ecs_cluster_name

    create_ecs_task(ecs_client, ecs_task_family, ecs_cluster_name, settings, ENVIRONMENT, "HYPATIO")
    create_ecs_task(ecs_client, ecs_task_family, ecs_cluster_name, settings, ENVIRONMENT, "SCIAUTH")
    create_ecs_task(ecs_client, ecs_task_family, ecs_cluster_name, settings, ENVIRONMENT, "SCIAUTHZ")




