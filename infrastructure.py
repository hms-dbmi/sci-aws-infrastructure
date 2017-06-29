import boto3
import argparse
import sys

sys.path.insert(0, "/Users/mtmcduffie/src/devops/aws-python-utilities")

from ecs import create_ecs_cluster, create_ecs_ec2, add_policy_to_ecs_task_role, create_ecs_task, create_ecs_task_role, create_ecs_service
from security_group import create_security_groups, create_db_security_groups, add_ingress_to_sg
from utilities import read_settings_file, read_key_file
from populate_vault import (
    populate_vault_django_secret,
    populate_vault_auth0_full,
    populate_vault_registration_services,
    secret_to_vault)
from rds import create_db_subnet, create_db, create_database_for_task
from subnets import create_db_subnets
from parameter_store import secret_to_ps, create_key, create_key_policy, create_parameter_access_policy
from populate_parameter_store import populate_ps_auth0, populate_ps_django_secret, populate_ps_auth0_full
from codepipeline import create_pipeline
from codebuild import create_codebuild
from botocore.exceptions import ClientError

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
ssm_client = boto3.client('ssm')

ENVIRONMENT = settings["ENVIRONMENT"]

stack_name = settings["STACK_NAME"] + "-" + ENVIRONMENT

ecs_cluster_name = settings["STACK_NAME"] + "-" + ENVIRONMENT

userdata_string = "#!/bin/bash\necho ECS_CLUSTER=" + ecs_cluster_name + " >> /etc/ecs/ecs.config"

MYSQL_USERNAME = "root"
MYSQL_PORT = "3306"

secret_list = {"SCIAUTH":[
                        {"secret_name": "mysql_username", "secret_value": "sciauth"},
                        {"secret_name": "mysql_port", "secret_value": MYSQL_PORT},
                        {"secret_name": "cookie_domain", "secret_value": settings["COOKIE_DOMAIN"]}
                ,],
               "SCIREG":[
                        {"secret_name": "mysql_username", "secret_value": "scireg"},
                        {"secret_name": "mysql_port", "secret_value": MYSQL_PORT},
                        {"secret_name": "email_salt", "secret_value": settings["EMAIL_SALT"]},
                        {"secret_name": "confirm_email_url", "secret_value": settings["CONFIRM_EMAIL_URL"]},
                        {"secret_name": "cookie_domain", "secret_value": settings["COOKIE_DOMAIN"]},
                        {"secret_name": "email_host", "secret_value": settings["EMAIL_HOST"]},
                        {"secret_name": "email_host_user", "secret_value": settings["EMAIL_HOST_USER"]},
                        {"secret_name": "email_host_password", "secret_value": settings["EMAIL_HOST_PASSWORD"]},
                        {"secret_name": "email_port", "secret_value": settings["EMAIL_PORT"]},
                      ]}

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

if steps["CREATE_SERVICE"] == "True":

    TASK_NAMES = ["SCIAUTH", "SCIREG"]

    for task_name in TASK_NAMES:
        try:
            create_ecs_service(ecs_client, ecs_cluster_name, ecs_cluster_name + "-" + task_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidParameterException':
                print("Error: %s" % e)

if steps["CREATE_TASK_ROLE"] == "True":

    TASK_NAMES = ["SCIAUTH", "SCIREG"]

    for task_name in TASK_NAMES:

        vault_path = settings["VAULT_PROJECT_NAME"] + "/" + task_name.lower() + "/" + ENVIRONMENT.upper()

        create_parameter_access_policy(stack_name + "-" + task_name, vault_path.replace("/", ".") + "*", settings)
        create_ecs_task_role(stack_name + "-" + task_name)

if steps["CREATE_KEY_FOR_AWS_PS"] == "True":

    TASK_NAMES = ["SCIAUTH", "SCIREG"]

    for task_name in TASK_NAMES:

        try:
            create_key(stack_name + "-" + task_name, settings)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AlreadyExistsException':
                print("Error: %s" % e)

        try:
            create_key_policy(stack_name + "-" + task_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'EntityAlreadyExists':
                print("Error: %s" % e)


if steps["ADD_POLICY_TO_ECS_TASK_ROLE"] == "True":

    TASK_NAMES = ["SCIAUTH", "SCIREG"]

    for task_name in TASK_NAMES:
        add_policy_to_ecs_task_role(stack_name + "-" + task_name, settings)

if steps["CREATE_TASK_HYPATIO"] == "True":
    ecs_task_family = ecs_cluster_name

    create_ecs_task(ecs_client, ecs_task_family, ecs_cluster_name, settings, ENVIRONMENT.lower(), "HYPATIO")

if steps["CREATE_TASK_SCIAUTH"] == "True":
    ecs_task_family = ecs_cluster_name

    create_ecs_task(ecs_client, ecs_task_family, ecs_cluster_name, settings, ENVIRONMENT.lower(), "SCIAUTH", "arn:aws:iam::685606823951:role/SCI-DEV-SCIAUTH-TASK-ROLE")

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

    vault_path_sciauthz = settings["VAULT_PROJECT_NAME"] + "/sciauthz/" + ENVIRONMENT.lower()
    vault_path_scireg = settings["VAULT_PROJECT_NAME"] + "/scireg/" + ENVIRONMENT.lower()

    populate_vault_django_secret(settings, ENVIRONMENT.lower(), "sciauthz")
    populate_vault_django_secret(settings, ENVIRONMENT.lower(), "scireg")

    populate_vault_auth0_full(settings, ENVIRONMENT.lower(), "sciauthz")
    populate_vault_auth0_full(settings, ENVIRONMENT.lower(), "scireg")

    populate_vault_registration_services(settings, "scireg/" + ENVIRONMENT.lower(), "SCIREG")

    secret_to_vault(settings, vault_path_sciauthz + "/mysql_username", "sciauthz")
    secret_to_vault(settings, vault_path_sciauthz + "/mysql_port", MYSQL_PORT)

    secret_to_vault(settings, vault_path_scireg + "/ssl_key", read_key_file(settings["SSL_KEY_FILE_SCIREG"]).decode("utf-8"))
    secret_to_vault(settings, vault_path_scireg + "/ssl_cert_chain", read_key_file(settings["SSL_CERT_CHAIN_FILE_SCIREG"]).decode("utf-8"))

    secret_to_vault(settings, vault_path_sciauthz + "/ssl_key", read_key_file(settings["SSL_KEY_FILE_SCIAUTHZ"]).decode("utf-8"))
    secret_to_vault(settings, vault_path_sciauthz + "/ssl_cert_chain", read_key_file(settings["SSL_CERT_CHAIN_FILE_SCIAUTHZ"]).decode("utf-8"))


if steps["POPULATE_AWS_PARAMETER_STORE"] == "True":

    TASK_NAMES = ["SCIAUTH", "SCIREG"]

    for task_name in TASK_NAMES:

        current_secret_list = secret_list[task_name]

        vault_path = settings["VAULT_PROJECT_NAME"] + "/" + task_name.lower() + "/" + ENVIRONMENT.upper() + "/"

        key_name = stack_name + "-" + task_name + "-KEY"

        ssl_key = read_key_file(settings["SSL_KEY_FILE_" + task_name])
        current_secret_list.append({"secret_name": "ssl_key", "secret_value": ssl_key.decode("utf-8")})

        dry_run = True if settings["PARAMETER_STORE_DRY_RUN"] == "True" else False

        for secret in current_secret_list:
            secret_to_ps(ssm_client, vault_path + secret["secret_name"], secret["secret_value"], key_name, dry_run)

        populate_ps_django_secret(settings, ssm_client, ENVIRONMENT.upper(), task_name.lower(), key_name, dry_run)
        populate_ps_auth0(settings, ssm_client, ENVIRONMENT.upper(), task_name.lower(), key_name, dry_run)

        if task_name == "SCIAUTH":
            populate_ps_auth0_full(settings, ssm_client, ENVIRONMENT.upper(), task_name.lower(), key_name, dry_run)

        # I know, I know. The Cert is too long for one SecureString. Split it to multiple secrets.
        split_string = lambda x, n: [x[i:i + n] for i in range(0, len(x), n)]

        ssl_cert = read_key_file(settings["SSL_CERT_CHAIN_FILE_" + task_name]).decode("utf-8")

        ssl_cert = split_string(ssl_cert, 4000)

        secret_to_ps(ssm_client, vault_path + "ssl_cert_chain1", ssl_cert[0], key_name, dry_run)
        secret_to_ps(ssm_client, vault_path + "ssl_cert_chain2", ssl_cert[1], key_name, dry_run)
        secret_to_ps(ssm_client, vault_path + "ssl_cert_chain3", ssl_cert[2], key_name, dry_run)

        secret_to_ps(ssm_client, vault_path + "mysql_host", settings["DB_HOST"], key_name, dry_run)
        secret_to_ps(ssm_client, vault_path + "mysql_pw", settings["DB_PW"], key_name, dry_run)

if steps["POPULATE_VAULT_HYPATIO"] == "True":
    vault_path_hypatio = settings["VAULT_PROJECT_NAME"] + "/hypatio/" + ENVIRONMENT.lower()

    populate_vault_django_secret(settings, ENVIRONMENT.lower(), "hypatio")
    populate_vault_auth0_full(settings, ENVIRONMENT.lower(), "hypatio")
    populate_vault_registration_services(settings, "hypatio/" + ENVIRONMENT.lower(), "HYPATIO")

    secret_to_vault(settings, vault_path_hypatio + "/authentication_login_url", settings["ACCOUNT_SERVER_URL"])
    secret_to_vault(settings, vault_path_hypatio + "/register_user_url", settings["SCIREG_URL"])
    secret_to_vault(settings, vault_path_hypatio + "/authorization_server_url", settings["PERMISSION_SERVER_URL"])

    secret_to_vault(settings, vault_path_hypatio + "/ssl_key", read_key_file(settings["SSL_KEY_FILE_HYPATIO"]).decode("utf-8"))
    secret_to_vault(settings, vault_path_hypatio + "/ssl_cert_chain", read_key_file(settings["SSL_CERT_CHAIN_FILE_HYPATIO"]).decode("utf-8"))

    secret_to_vault(settings, vault_path_hypatio + "/cookie_domain", settings["COOKIE_DOMAIN"])

    secret_to_vault(settings, vault_path_hypatio + "/authentication_login_url", settings["ACCOUNT_SERVER_URL"])

if steps["ADD_SG_IO"] == "True":

    # This lets anyone hit the Hypatio server.
    add_ingress_to_sg(stack_name, vpc, "0.0.0.0/0", 80, 80)
    add_ingress_to_sg(stack_name, vpc, "0.0.0.0/0", 443, 443)

    # This lets anyone hit the authentication server.
    add_ingress_to_sg(stack_name, vpc, "0.0.0.0/0", 8001, 8001)

    # This lets anyone hit the authorization server.
    add_ingress_to_sg(stack_name, vpc, "0.0.0.0/0", 8003, 8003)

    # This lets anyone hit the Registration server.
    add_ingress_to_sg(stack_name, vpc, "0.0.0.0/0", 8005, 8005)

if steps["CREATE_CODEBUILD"] == "True":

    TASK_NAMES = ["SCIAUTH", "SCIREG"]

    for task_name in TASK_NAMES:

        create_codebuild(stack_name + "-" + task_name, task_name.lower(), ENVIRONMENT.lower(), settings)

if steps["CREATE_CODEPIPELINE"] == "True":

    TASK_NAMES = ["SCIAUTH", "SCIREG"]

    for task_name in TASK_NAMES:

        secret_path = settings["VAULT_PROJECT_NAME"] + "/" + task_name.lower()

        create_pipeline(stack_name, ENVIRONMENT, task_name, settings, secret_path)