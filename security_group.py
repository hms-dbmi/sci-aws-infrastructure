def create_security_groups(stack_name, vpc, settings):

    protected_cidr = settings["PROTECTED_CIDR"]

    print("Creating Security Groups")
    security_group_name = stack_name + '_SG'
    security_group_description = stack_name + ' HTTP/HTTPS/SSH SG'

    new_security_group = vpc.create_security_group(GroupName=security_group_name,
                                                   Description=security_group_description)

    new_security_group.create_tags(Tags=[{'Key': 'Name', 'Value': security_group_name}])

    new_security_group.authorize_ingress(CidrIp=protected_cidr, FromPort=443, ToPort=443, IpProtocol="tcp")
