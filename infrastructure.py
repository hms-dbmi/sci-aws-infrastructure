import boto3
import argparse
import sys

sys.path.insert(0, "/Users/mtmcduffie/src/devops/aws-python-utilities")

from ecs import create_ecs_cluster, create_ecs_ec2, create_ecs_task
from security_group import create_security_groups, create_db_security_groups, add_ingress_to_sg
from utilities import read_settings_file, read_key_file
from populate_vault import populate_vault_django_secret, populate_vault_auth0_full, populate_vault_registration_services, secret_to_vault
from rds import create_db_subnet, create_db, create_database_for_task
from subnets import create_db_subnets

parser = argparse.ArgumentParser()
parser.add_argument("settings_file")
args = parser.parse_args()

settings = read_settings_file(args.settings_file)
steps = read_settings_file("steps")

vpc_id = settings["VPC_ID"]

ec2 = boto3.resource('ec2')
vpc = ec2.Vpc(vpc_id)
ecs_client = boto3.client('ecs')
rds_client = boto3.client('rds')

ENVIRONMENT = settings["ENVIRONMENT"]

stack_name = settings["STACK_NAME"] + "-" + ENVIRONMENT

ecs_cluster_name = settings["STACK_NAME"] + "-" + ENVIRONMENT

userdata_string = "#!/bin/bash\necho ECS_CLUSTER=" + ecs_cluster_name + " >> /etc/ecs/ecs.config"

if steps["CREATE_DB_SUBNETS"] == "True":
    create_db_subnets(vpc, stack_name, settings["CIDR_BLOCK_START"])

if steps["CREATE_SECURITY_GROUP"] == "True":
    create_security_groups(stack_name, vpc, settings)

if steps["CREATE_DB_SECURITY_GROUP"] == "True":
    create_db_security_groups(stack_name, vpc)

if steps["CREATE_DB_SUBNET_GROUP"] == "True":
    create_db_subnet(stack_name, rds_client, vpc)

if steps["CREATE_CLUSTER"] == "True":
    create_ecs_cluster(ecs_client, ecs_cluster_name)

if steps["CREATE_ECS_EC2"] == "True":
    create_ecs_ec2(stack_name, ecs_cluster_name, vpc, ec2, userdata_string, settings, ENVIRONMENT)

if steps["CREATE_TASK_HYPATIO"] == "True":
    ecs_task_family = ecs_cluster_name

    create_ecs_task(ecs_client, ecs_task_family, ecs_cluster_name, settings, ENVIRONMENT.lower(), "HYPATIO")

if steps["CREATE_TASK_SCIAUTH"] == "True":
    ecs_task_family = ecs_cluster_name

    create_ecs_task(ecs_client, ecs_task_family, ecs_cluster_name, settings, ENVIRONMENT.lower(), "SCIAUTH")

if steps["CREATE_TASK_SCIAUTHZ"] == "True":
    ecs_task_family = ecs_cluster_name

    create_ecs_task(ecs_client, ecs_task_family, ecs_cluster_name, settings, ENVIRONMENT.lower(), "SCIAUTHZ")

if steps["CREATE_TASK_SCIREG"] == "True":
    ecs_task_family = ecs_cluster_name

    create_ecs_task(ecs_client, ecs_task_family, ecs_cluster_name, settings, ENVIRONMENT.lower(), "SCIREG")

if steps["CREATE_RDS"] == "True":
    create_db(stack_name, vpc, rds_client, settings, ENVIRONMENT, "SCI")

if steps["CREATE_DBS"] == "True":
    create_database_for_task(settings, "SCI", "HYPATIO", ENVIRONMENT)
    create_database_for_task(settings, "SCI", "SCIAUTH", ENVIRONMENT)
    create_database_for_task(settings, "SCI", "SCIAUTHZ", ENVIRONMENT)
    create_database_for_task(settings, "SCI", "SCIREG", ENVIRONMENT)

if steps["POPULATE_VAULT"] == "True":
    # vault token-create -policy="sci-dev-write" -policy="sci-auth-dev-write" -policy="sci-authz-dev-write" -policy="scireg-dev-write" -policy="hypatio-dev-write" -ttl="300m" -format="json" | jq -r .auth.client_token
    # vault token-create -policy="sci-prod-write" -policy="sci-auth-prod-write" -policy="sci-authz-prod-write" -policy="scireg-prod-write" -policy="hypatio-prod-write" -ttl="300m" -format="json" | jq -r .auth.client_token

    MYSQL_USERNAME = "root"
    MYSQL_PORT = "3306"

    vault_path_sciauth = settings["VAULT_PROJECT_NAME"] + "/sciauth/" + ENVIRONMENT.lower()
    vault_path_sciauthz = settings["VAULT_PROJECT_NAME"] + "/sciauthz/" + ENVIRONMENT.lower()
    vault_path_scireg = settings["VAULT_PROJECT_NAME"] + "/scireg/" + ENVIRONMENT.lower()

    populate_vault_django_secret(settings, ENVIRONMENT.lower(), "sciauth")
    populate_vault_django_secret(settings, ENVIRONMENT.lower(), "sciauthz")
    populate_vault_django_secret(settings, ENVIRONMENT.lower(), "scireg")

    populate_vault_auth0_full(settings, ENVIRONMENT.lower(), "sciauth")
    populate_vault_auth0_full(settings, ENVIRONMENT.lower(), "scireg")

    populate_vault_registration_services(settings, "scireg/" + ENVIRONMENT.lower(), "SCIREG")

    secret_to_vault(settings, vault_path_sciauth + "/mysql_username", "sciauth")
    secret_to_vault(settings, vault_path_sciauth + "/mysql_port", MYSQL_PORT)

    secret_to_vault(settings, vault_path_sciauthz + "/mysql_username", "sciauthz")
    secret_to_vault(settings, vault_path_sciauthz + "/mysql_port", MYSQL_PORT)

    secret_to_vault(settings, vault_path_scireg + "/mysql_username", "scireg")
    secret_to_vault(settings, vault_path_scireg + "/mysql_port", MYSQL_PORT)
    secret_to_vault(settings, vault_path_scireg + "/email_salt", settings["EMAIL_SALT"])
    secret_to_vault(settings, vault_path_scireg + "/confirm_email_url", settings["CONFIRM_EMAIL_URL"])

    secret_to_vault(settings, vault_path_scireg + "/email_host", settings["EMAIL_HOST"])
    secret_to_vault(settings, vault_path_scireg + "/email_host_user", settings["EMAIL_HOST_USER"])
    secret_to_vault(settings, vault_path_scireg + "/email_host_password", settings["EMAIL_HOST_PASSWORD"])
    secret_to_vault(settings, vault_path_scireg + "/email_port", settings["EMAIL_PORT"])

    secret_to_vault(settings, vault_path_sciauth + "/ssl_key", read_key_file(settings["SSL_KEY_FILE_SCIAUTH"]).decode("utf-8"))
    secret_to_vault(settings, vault_path_sciauth + "/ssl_cert_chain", read_key_file(settings["SSL_CERT_CHAIN_FILE_SCIAUTH"]).decode("utf-8"))

    secret_to_vault(settings, vault_path_sciauthz + "/ssl_key", read_key_file(settings["SSL_KEY_FILE_SCIAUTHZ"]).decode("utf-8"))
    secret_to_vault(settings, vault_path_sciauthz + "/ssl_cert_chain", read_key_file(settings["SSL_CERT_CHAIN_FILE_SCIAUTHZ"]).decode("utf-8"))

    secret_to_vault(settings, vault_path_scireg + "/ssl_key", read_key_file(settings["SSL_KEY_FILE_SCIREG"]).decode("utf-8"))
    secret_to_vault(settings, vault_path_scireg + "/ssl_cert_chain", read_key_file(settings["SSL_CERT_CHAIN_FILE_SCIREG"]).decode("utf-8"))


if steps["POPULATE_VAULT_HYPATIO"] == "True":
    populate_vault_django_secret(settings, ENVIRONMENT.lower(), "hypatio")
    populate_vault_auth0_full(settings, ENVIRONMENT.lower(), "hypatio")
    populate_vault_registration_services(settings, "hypatio/" + ENVIRONMENT.lower(), "HYPATIO")

if steps["ADD_SG_IO"] == "True":

    # This lets anyone hit the Registration server.
    add_ingress_to_sg(stack_name, vpc, "0.0.0.0/0", 8005, 8005)
