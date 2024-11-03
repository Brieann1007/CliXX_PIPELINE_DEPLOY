#!/usr/bin/python

import boto3,botocore
from botocore.exceptions import ClientError
import time
import base64
import os
import sys

def save_to_ssm(param_name, param_value):
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        ssm.put_parameter(
            Name=param_name,
            Value=param_value,
            Type='String',
            Overwrite=True
        )
        print(f"Parameter {param_name} saved in SSM.")
    except ClientError as e:
        print(f"Error saving {param_name} to SSM: {e}")
        sys.exit()

def create_vpc(**args):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ##creating VPC##
    try:
        ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
        response = ec2.create_vpc(
            CidrBlock='10.0.0.0/16',
            AmazonProvidedIpv6CidrBlock=False
        )
        vpc_id = response['Vpc']['VpcId']
        print('Created VPC with ID: %s.' % (vpc_id))
        
         # Enable DNS hostnames
        ec2.modify_vpc_attribute(
        VpcId=vpc_id,
        EnableDnsSupport={'Value': True}
        )
        ec2.modify_vpc_attribute(
        VpcId=vpc_id,
        EnableDnsHostnames={'Value': True}
        )
    
        print('DNS hostnames enabled for the VPC.')
        response = ec2.create_tags(
        Resources=[vpc_id],
        Tags=[
            {
                'Key': 'Name',
                'Value': 'CliXX-VPC-boto'
            }
        ]
        )
        
        print('VPC tagged with name: CliXX-VPC-boto')
        # Retrieve the tags for the created VPC
        tags = ec2.describe_tags(
        Filters=[
            {
                'Name': 'resource-id',
                'Values': [vpc_id]
            }
        ]
        )

        # Print the value of the 'Name' tag
        for tag in tags['Tags']:
            if tag['Key'] == 'Name':
                print('Value of Name tag: %s.' % (tag["Value"]))

        save_to_ssm('/clixx/vpc_id', vpc_id)
        
        return vpc_id
    
    except ClientError as e:
        print(e)
           
def create_subnets(vpc_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ##creating security group##
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    # Get availability zones
    availability_zones = [az['ZoneName'] for az in ec2.describe_availability_zones()['AvailabilityZones']]
    print(availability_zones)
    public_subnet_ids = []
    private_subnet_ids = []

    for i, az in enumerate(availability_zones):
        # Create public subnets
        public_subnet_cidr = '10.0.%s.0/24' % i
        public_subnet_response = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=public_subnet_cidr,
            AvailabilityZone=az
        )
        public_subnet_id = public_subnet_response['Subnet']['SubnetId']
        public_subnet_ids.append(public_subnet_id)
        print(public_subnet_id)
        ec2.modify_subnet_attribute(
            SubnetId=public_subnet_id,
            MapPublicIpOnLaunch={
                'Value': True           # Enable public IP for instances in this subnet
            }
        )
        print('Created public subnet with ID: %s in %s' % (public_subnet_id, az))
        # Tag public subnet
        ec2.create_tags(
            Resources=[public_subnet_id],
            Tags=[{'Key': 'Name', 'Value': 'clixx-public-subnet-%s' % (i+1)}]
        )
        # Create private subnets
        private_subnet_cidr = '10.0.%s.0/24' % (i + 10)  # Ability to adjust as necessary for private subnets
        private_subnet_response = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=private_subnet_cidr,
            AvailabilityZone=az
        )
        private_subnet_id = private_subnet_response['Subnet']['SubnetId']
        private_subnet_ids.append(private_subnet_id)
        print('Created private subnet with ID: %s in %s' % (private_subnet_id,az))
        ec2.create_tags(
            Resources=[private_subnet_id],
            Tags=[{'Key': 'Name', 'Value': 'clixx-private-subnet-%s' % (i+1)}]
        )
    try:
        ssm.put_parameter(Name='/clixx/public_subnet_ids', Value=','.join(public_subnet_ids), Type='String', Overwrite=True)
        ssm.put_parameter(Name='/clixx/private_subnet_ids', Value=','.join(private_subnet_ids), Type='String', Overwrite=True)
        print('Public and private subnet IDs saved to SSM Parameter Store.')
    except ClientError as e:
        print("Error saving subnet IDs to SSM: %s" % (e))
        
    return public_subnet_ids, private_subnet_ids
   
def create_internet_gateway(vpc_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ##creating security group##
    
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')

    # Create Internet Gateway
    ig_response = ec2.create_internet_gateway()
    ig_id = ig_response['InternetGateway']['InternetGatewayId']
    print('Created Internet Gateway with ID: %s' % (ig_id))

    # Attach Internet Gateway to VPC
    ec2.attach_internet_gateway(InternetGatewayId=ig_id, VpcId=vpc_id)
    print('Attached Internet Gateway to VPC: %s' % (vpc_id))
     # Tag the Internet Gateway
    ec2.create_tags(Resources=[ig_id], Tags=[{'Key': 'Name', 'Value': 'clixx-boto-igw'}])
    save_to_ssm('/clixx/internetgateway_id', ig_id)
    return ig_id

def create_nat_gateway(vpc_id, public_subnet_ids):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ##creating security group##
    
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')

    # Create Elastic IP for NAT Gateway
    eip_response = ec2.allocate_address(Domain='vpc')
    eip_id = eip_response['AllocationId']
    print('Created Elastic IP with ID: %s' % (eip_id))

    # Create NAT Gateway in the first public subnet
    nat_response = ec2.create_nat_gateway(
        SubnetId=public_subnet_ids[0],
        AllocationId=eip_id
    )
    nat_gateway_id = nat_response['NatGateway']['NatGatewayId']
    print('Created NAT Gateway with ID: %s' % (nat_gateway_id))
    # Tag the NAT Gateway
    ec2.create_tags(Resources=[nat_gateway_id], Tags=[{'Key': 'Name', 'Value': 'clixx-boto-natgw'}])
    save_to_ssm('/clixx/natgateway_id', nat_gateway_id)
    save_to_ssm('/clixx/eip_id', eip_id)
    
    # Wait for the NAT Gateway to become available
    print("Waiting for NAT Gateway to become available...")
    while True:
        response = ec2.describe_nat_gateways(NatGatewayIds=[nat_gateway_id])
        nat_gateway_status = response['NatGateways'][0]['State']
        if nat_gateway_status == 'available':
            print('NAT Gateway %s is now available.' % (nat_gateway_id))
            break
        elif nat_gateway_status == 'failed':
            print('NAT Gateway %s creation failed.' % (nat_gateway_id))
            return None, eip_id
        else:
            print('NAT Gateway %s status: %s. Retrying in 30 seconds...' % (nat_gateway_id,nat_gateway_status))
            time.sleep(30)
            
    return nat_gateway_id, eip_id

def create_route_table(vpc_id, public_subnet_ids, ig_id, private_subnet_ids, nat_gateway_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    # Create Public Route Table
    public_rt_response = ec2.create_route_table(VpcId=vpc_id)
    public_rt_id = public_rt_response['RouteTable']['RouteTableId']
    print('Created Public Route Table with ID: %s' % (public_rt_id))
    # Tag the Route Table
    ec2.create_tags(Resources=[public_rt_id], Tags=[{'Key': 'Name', 'Value': 'clixx-public-boto-rtb'}])
    
    # Create route to Internet Gateway in Public Route Table
    ec2.create_route(
        RouteTableId=public_rt_id,
        DestinationCidrBlock='0.0.0.0/0',
        GatewayId=ig_id
    )
    
    print('Created route in Public Route Table to Internet Gateway: %s' % (ig_id))

    # Associate Public Route Table with Public Subnets
    for public_subnet_id in public_subnet_ids:
        ec2.associate_route_table(RouteTableId=public_rt_id, SubnetId=public_subnet_id)
        print('Associated Public Route Table with Public Subnet: %s' % (public_subnet_id))

    # Create Private Route Table
    private_rt_response = ec2.create_route_table(VpcId=vpc_id)
    private_rt_id = private_rt_response['RouteTable']['RouteTableId']
    print('Created Private Route Table with ID: %s' % (private_rt_id))

    # Create route to NAT Gateway in Private Route Table
    ec2.create_route(
        RouteTableId=private_rt_id,
        DestinationCidrBlock='0.0.0.0/0',
        NatGatewayId=nat_gateway_id
    )
    print('Created route in Private Route Table to NAT Gateway: %s' % (nat_gateway_id))

    # Associate Private Route Table with Private Subnets
    for private_subnet_id in private_subnet_ids:
        ec2.associate_route_table(RouteTableId=private_rt_id, SubnetId=private_subnet_id)
        print('Associated Private Route Table with Private Subnet: %s' % (nat_gateway_id))
        
    save_to_ssm('/clixx/publicroutetable', public_rt_id)
    save_to_ssm('/clixx/privateroutetable', private_rt_id)    
    return public_rt_id, private_rt_id
        
def create_security_group(vpc_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ##creating security group##
    try:
        ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
        response = ec2.create_security_group(
        Description='stack_web_dmz_cli',
        GroupName='stack_web_dmz_cli',
        VpcId = vpc_id
        )
        VpcId = vpc_id
        print(response)
        security_group_id = response['GroupId']
        print('Security Group Created %s in vpc %s.' % (security_group_id, VpcId))
        data = ec2.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 80,
             'ToPort': 80,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp',
             'FromPort': 443,
             'ToPort': 443,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp',
             'FromPort': 2049,
             'ToPort': 2049,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp',
             'FromPort': 3306,
             'ToPort': 3306,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ])
        print('Ingress Successfully Set %s' % data)
        save_to_ssm('/clixx/securitygroup_id', security_group_id)
        
        return security_group_id
    
    except ClientError as e:
        print(e)
        
def create_file_system():
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    efs=boto3.client('efs',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    response=efs.create_file_system(
    CreationToken='tokenstring',
    PerformanceMode='generalPurpose',
    Encrypted=True,
    KmsKeyId='15a7670d-cdec-4cb6-b89a-8e6a0d492c13',
    ThroughputMode='bursting',
    #ProvisionedThroughputInMibps=123.0,
    AvailabilityZoneName='us-east-1a',
    Backup=True,
    Tags=[
        {
            'Key': 'Name',
            'Value': 'stack-CliXX-efs-cli'
        },
        {
            'Key': 'GroupName',
            'Value': 'stackcloud12'
        },
        {
            'Key': 'OwnerEmail',
            'Value': 'brieann1007@outlook.com'
        }
        ]
    )
    # Extract the File System ID
    file_system_id = response['FileSystemId']
    print("EFS File System created with ID:", file_system_id)
    save_to_ssm('/clixx/efs', file_system_id)
    return file_system_id
    
def create_target_group(vpc_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    elbv2=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    response=elbv2.create_target_group(
        Name='stack-CliXX-tg-cli-boto',
        Protocol='HTTP',
        ProtocolVersion='HTTP1',
        Port=80,
        VpcId=vpc_id,
        HealthCheckProtocol='HTTP',
        HealthCheckPort='traffic-port',
        HealthCheckEnabled=True,
        HealthCheckPath='/',
        HealthCheckIntervalSeconds=300,
        HealthCheckTimeoutSeconds=120,
        HealthyThresholdCount=5,
        UnhealthyThresholdCount=2,
        Matcher={
        'HttpCode': '200'
        },
        TargetType='instance',
        Tags=[
            {
                'Key': 'GroupName',
                'Value': 'stackcloud12'
            },
            {
                'Key': 'OwnerEmail',
                'Value': 'brieann1007@outlook.com'
            }
        ]
    )
    #print(response)
    tg_arn=response['TargetGroups'][0]['TargetGroupArn']
    print(tg_arn)
    save_to_ssm('/clixx/targetgroupARN', tg_arn)
    return tg_arn

def create_load_balancer(security_group_id,tg_arn, public_subnets):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    elbv2=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    # Create Application Load Balancer
    load_balancer_response = elbv2.create_load_balancer(
        Name='stack-clixx-lb-boto',
        Subnets=public_subnets,
        SecurityGroups=[security_group_id],
        Scheme='internet-facing',
        Tags=[
        {
            'Key': 'GroupName',
            'Value': 'stackcloud12'
        },
        ],
        Type='application'
    )
    load_balancer_arn = load_balancer_response['LoadBalancers'][0]['LoadBalancerArn']
    load_balancer_dns = load_balancer_response['LoadBalancers'][0]['DNSName']

    print("Load Balancer created: %s" % (load_balancer_arn))
    print("Load Balancer DNS: %s" % (load_balancer_dns))
    
    # Create HTTPS listener
    elbv2.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol='HTTPS',
        Port=443,
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': tg_arn}],
        Certificates=[{'CertificateArn': 'arn:aws:acm:us-east-1:054037131148:certificate/6921bcbd-b15a-4739-8a75-4c26eba36462'}]
    )
    
    # Create HTTP listener
    elbv2.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol='HTTP',
        Port=80,
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': tg_arn}]
    )
    
    print("Listeners created.")
    time.sleep(60)
    response = elbv2.describe_load_balancers(
    LoadBalancerArns=[load_balancer_arn],
    )
    print(response)
    save_to_ssm('/clixx/LoadBalancerARN', load_balancer_arn)
    save_to_ssm('/clixx/LoadbalancerDNS', load_balancer_dns)
    return load_balancer_arn, load_balancer_dns   

def create_rds_instance(vpc_id, private_subnets, security_group_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    rds=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    db_subnet_group_response = rds.create_db_subnet_group(
        DBSubnetGroupName='clixx-db-subnet-group',
        DBSubnetGroupDescription='Subnet group for RDS',
        SubnetIds=private_subnets
    )

    print("DB Subnet Group created: %s" % (db_subnet_group_response['DBSubnetGroup']['DBSubnetGroupName']))

    rds_instance_response = rds.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier='stack-clixx-db',
        DBSnapshotIdentifier='arn:aws:rds:us-east-1:577701061234:snapshot:wordpressdbclixx-ecs-snap',
        DBInstanceClass='db.m6g.large',
        VpcSecurityGroupIds=[security_group_id],
        DBSubnetGroupName='clixx-db-subnet-group',
        Port=3306,
        PubliclyAccessible=False
    )
    
    rds_identifier = rds_instance_response['DBInstance']['DBInstanceIdentifier']
    print("RDS instance created: %s" % (rds_identifier))
    save_to_ssm('/clixx/db_instance_identifier', rds_identifier)
     # Wait for the RDS instance to be available and retrieve its endpoint
    while True:
        response = rds.describe_db_instances(DBInstanceIdentifier=rds_identifier)
        db_instance = response['DBInstances'][0]
        if db_instance['DBInstanceStatus'] == 'available':
            endpoint_address = db_instance['Endpoint']['Address']
            print("RDS Endpoint Address: %s" % (endpoint_address))
            try:
                ssm.put_parameter(Name='/clixx/db_endpoint_address', Value=endpoint_address, Type='String', Overwrite=True)
                print("Endpoint address saved to SSM Parameter Store.")
            except ClientError as e:
                print("Error saving endpoint address to SSM: %s" % (e))
            break
        else:
            print("Waiting for RDS instance to become available...")
            time.sleep(30)  # Wait 30 seconds before checking again
    
    return rds_identifier

def get_ssm_parameter(parameter_name):
    """Retrieve a parameter from AWS SSM Parameter Store."""
    ssm = boto3.client('ssm', region_name='us-east-1')
    response = ssm.get_parameter(Name=parameter_name)
    return response['Parameter']['Value']

def create_autoscaling_group(load_balancer_dns, security_group_id, tg_arn, public_subnets, file_system_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    load_balancer_dns = get_ssm_parameter('/clixx/LoadbalancerDNS')
    file_system_id = get_ssm_parameter('/clixx/efs')
    rds_endpoint_address = get_ssm_parameter('/clixx/db_endpoint_address')
    autoscaling=boto3.client('autoscaling',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    user_data_script = """#!/bin/bash -xe
    # Variables
    DNS='%s'
    FILE_SYSTEM_ID='%s'
    DB_ADDRESS='%s'
    # Update packages and install needed tools
    sudo yum update -y
    sudo yum install -y nfs-utils git httpd mariadb-server
    sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
    # Mounting EFS
    AVAILABILITY_ZONE=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
    REGION=${AVAILABILITY_ZONE:0:-1}
    MOUNT_POINT=/var/www/html
    sudo mkdir -p ${MOUNT_POINT}
    sudo chown ec2-user:ec2-user ${MOUNT_POINT}
    echo "${FILE_SYSTEM_ID}.efs.${REGION}.amazonaws.com:/ ${MOUNT_POINT} nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0" | sudo tee -a /etc/fstab
    sudo mount -a
    sudo chmod -R 755 /var/www/html
    # Enable and start Apache service
    sudo systemctl enable httpd
    sudo systemctl start httpd
    # Configure permissions for /var/www
    sudo usermod -a -G apache ec2-user
    sudo chown -R ec2-user:apache /var/www
    sudo chmod 2775 /var/www
    find /var/www -type d -exec sudo chmod 2775 {} \;
    find /var/www -type f -exec sudo chmod 0664 {} \;
    # Install WordPress if not already present
    cd /var/www/html
    if [ ! -f wp-config.php ]; then
        echo "wp-config.php does not exist, cloning repository..."
        git clone https://github.com/stackitgit/CliXX_Retail_Repository.git
        cp -r CliXX_Retail_Repository/* /var/www/html
    else
        echo "wp-config.php already exists"
    fi
    # Update Apache configuration to allow WordPress permalinks
    sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf
    sudo sed -i 's/wordpress-db.cc5iigzknvxd.us-east-1.rds.amazonaws.com/${DB_ADDRESS}/' /var/www/html/wp-config.php
    # Verify and update DNS in the database
    output_variable=$(mysql -u wordpressuser -pW3lcome123 -h ${DB_ADDRESS} -D wordpressdb -sse "SELECT option_value FROM wp_options WHERE option_value LIKE 'FinalCliXX-LB%';")
    if [ "$output_variable" == "${DNS}" ]; then
        echo "DNS Address found in the table"
    else
        echo "DNS Address not found in the table, updating..."
        mysql -u wordpressuser -pW3lcome123 -h ${DB_ADDRESS} -D wordpressdb <<EOF
        UPDATE wp_options SET option_value='${DNS}' WHERE option_value LIKE 'CliXX-APP-%';
    EOF
    fi
    # Grant file ownership and restart Apache
    sudo chown -R apache:apache /var/www
    sudo chmod 2775 /var/www
    find /var/www -type d -exec sudo chmod 2775 {} \;
    find /var/www -type f -exec sudo chmod 0664 {} \;
    sudo systemctl restart httpd
    """ % (load_balancer_dns, file_system_id, rds_endpoint_address)
    user_data_base64code = base64.b64encode(user_data_script.encode('utf-8')).decode('utf-8')
    
    # Get availability zones
    ec2=boto3.client('autoscaling',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    availability_zones = [az['ZoneName'] for az in ec2.describe_availability_zones()['AvailabilityZones']]
    print(availability_zones)
    launch_template_response = autoscaling.create_launch_template(
        LaunchTemplateName='stack-clixx-launch-template',
        LaunchTemplateData={
            'ImageId': 'ami-0ddc798b3f1a5117e',
            'InstanceType': 't3.micro',
            'SecurityGroupIds': [security_group_id],
            'UserData': user_data_base64code
                }
            )

    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName='stack-clixx-boto-asg',
        LaunchTemplate={
            'LaunchTemplateName': launch_template_response['LaunchTemplate']['LaunchTemplateName'],
            'Version': '$Latest'
        },
        MinSize=1,
        MaxSize=3,
        DesiredCapacity=1,
        AvailabilityZones=
        availability_zones,
        TargetGroupARNs=[
        tg_arn,
        ],
        VPCZoneIdentifier=','.join(public_subnets)
        )
    response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupName='stack-clixx-boto-asg'
    )
    
    if response['AutoScalingGroups']:
        asg_arn = response['AutoScalingGroups'][0]['AutoScalingGroupARN']
        print("AutoScaling Group ARN:", asg_arn)
        save_to_ssm('/clixx/AutoScalingGroups', asg_arn)
        return asg_arn
    else:
        print("AutoScaling Group not found.")
        return None
    
if __name__=="__main__":
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    vpc_id = create_vpc(service="ec2")
    public_subnets, private_subnets = create_subnets(vpc_id)
    ig_id = create_internet_gateway(vpc_id)
    nat_gateway_id, eip_id = create_nat_gateway(vpc_id, public_subnets)
    public_rt_id, private_rt_id = create_route_table(vpc_id, public_subnets, ig_id, private_subnets, nat_gateway_id)
    security_group_id = create_security_group(vpc_id)
    file_system_id = create_file_system()
    tg_arn = create_target_group(vpc_id)
    load_balancer_arn, load_balancer_dns= create_load_balancer(security_group_id,tg_arn, public_subnets)
    rds_identifier = create_rds_instance(vpc_id, private_subnets, security_group_id)
    asg_arn = create_autoscaling_group(load_balancer_dns, security_group_id, tg_arn, public_subnets, file_system_id)
    