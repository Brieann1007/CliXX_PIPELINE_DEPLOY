#!/usr/bin/python

import boto3,botocore
import os
import time

def delete_nat_gateway(nat_gateway_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ec2.delete_nat_gateway(NatGatewayId=nat_gateway_id)
    print('Deleted NAT Gateway with ID: %s' % (nat_gateway_id))

def unmap_public_ip(public_subnet_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    
    # Get instances in the public subnet
    instances = ec2.describe_instances(
        Filters=[{'Name': 'subnet-id', 'Values': [public_subnet_id]}]
    )

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            # Disassociate Elastic IPs or unmap public IPs as needed
            # Assuming EC2 instances have public IPs and need to be disassociated
            if 'PublicIpAddress' in instance:
                ec2.disassociate_address(AllocationId=instance['PublicIpAddress'])
                print('Unmapped public IP %s from instance %s' % (instance["PublicIpAddress"],instance["InstanceId"]))
def release_address(eip_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ec2.release_address(AllocationId=eip_id)
    print('Released Elastic IP with ID: %s' % (eip_id))
    
def delete_internet_gateway(ig_id, vpc_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ec2.detach_internet_gateway(InternetGatewayId=ig_id, VpcId=vpc_id)
    ec2.delete_internet_gateway(InternetGatewayId=ig_id)
    print('Deleted Internet Gateway with ID: %s' % (ig_id))

def delete_subnet(subnet_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ec2.delete_subnet(SubnetId=subnet_id)
    print('Deleted subnet with ID: %s' % (subnet_id))

def delete_security_group(security_group_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    response = ec2.delete_security_group(GroupId=security_group_id)
    print(response)
    
def delete_target_group(tg_arn):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    elbv2=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    elbv2.delete_target_group(TargetGroupArn=tg_arn)
    print('Deleted Target Group with ID: %s' % (tg_arn))
    
def delete_route_table(route_table_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ec2.delete_route_table(RouteTableId=route_table_id)
    print('Deleted Route Table with ID: %s' % (route_table_id))
    
def delete_load_balancer(load_balancer_arn):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    elbv2=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    elbv2.delete_load_balancer(LoadBalancerArn=load_balancer_arn)
    print("Deleted Load Balancer: %s" % (load_balancer_arn))
    
def delete_db_instance(rds_identifier):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    rds=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    rds.delete_db_instance(DBInstanceIdentifier=rds_identifier)
    print("Deleted RDS Instance: %s" % (rds_identifier))

def delete_vpc(vpc_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    response = ec2.delete_vpc(VpcId=vpc_id)
    print('Deleted VPC with ID: %s.' % (vpc_id))
    print(response)
    
def cleanup_resources(vpc_id, public_subnet_ids, private_subnet_ids, security_group_id, internet_gateway_id, nat_gateway_id, eip_id, route_table_ids, tg_arn, load_balancer_arn, rds_identifier):
    # Delete NAT Gateway
    delete_nat_gateway(nat_gateway_id)
    delete_load_balancer(load_balancer_arn)
    delete_db_instance(rds_identifier)
    time.sleep(580)
    release_address(eip_id)
    # Unmap public IPs before deleting resources
    for public_subnet_id in public_subnet_ids:
        unmap_public_ip(public_subnet_id)
    
    # Delete public subnets
    for subnet_id in public_subnet_ids:
        delete_subnet(subnet_id)

    # Delete private subnets
    for subnet_id in private_subnet_ids:
        delete_subnet(subnet_id)    
        
    delete_security_group(security_group_id)
    # Delete Internet Gateway
    delete_internet_gateway(internet_gateway_id, vpc_id)
    
    # Delete Route Tables
    for route_table_id in route_table_ids:
        delete_route_table(route_table_id)
    
    delete_target_group(tg_arn)
    
    
    
    time.sleep(190)
    delete_vpc(vpc_id)
    

if __name__=="__main__":
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    vpc_txt_loc='/codebuild/output/VPC/vpc.txt'
    if not os.path.exists(vpc_txt_loc):
        print("Error: The VPC ID file does not exist. Please run assume_role.py first.")
        exit(1)
        
    public_subnet_ids = []
    private_subnet_ids = []
    security_group_id = None
    internet_gateway_id = None
    nat_gateway_id = None
    eip_id = None
    route_table_ids = []
    tg_arn = None
    vpc_id = None
    load_balancer_arn = None
    rds_identifier = None
    
    with open(vpc_txt_loc, 'r') as f:
        vpc_id = f.readline().strip()
        # Read public subnets starting with 'subnet-'
        for line in f:
            line = line.strip()
            if line.startswith('subnet-'):
                public_subnet_ids.append(line)

            # Check if there are 6 public subnets, then move to private subnets
            if len(public_subnet_ids) == 6:
                break

        for line in f:
            line = line.strip()
            if line.startswith('subnet-'):
                private_subnet_ids.append(line)

            # Check if we have all private subnets
            if len(private_subnet_ids) == 6:
                break

        # Read security group ID starting with 'sg-'
        for line in f:
            line = line.strip()
            if line.startswith('sg-'):
                security_group_id = line
                break

        # Read internet gateway ID starting with 'igw-'
        for line in f:
            line = line.strip()
            if line.startswith('igw-'):
                internet_gateway_id = line
                break

        # Read NAT gateway ID starting with 'nat-'
        for line in f:
            line = line.strip()
            if line.startswith('nat-'):
                nat_gateway_id = line
                break
            
        # Read Elastic IP ID starting with 'eipalloc-'
        for line in f:
            line = line.strip()
            if line.startswith('eipalloc-'):
                eip_id = line
                break
            
        # Read Route table ID starting with 'rtb-'
        for line in f:
            line = line.strip()
            if line.startswith('rtb-'):
                route_table_ids.append(line)

            # Check if we have all route tables
            if len(route_table_ids) == 2:
                break
            
        # Read Target Group Arn starting with 'arn:aws:elasticloadbalancing:us-east-1:054037131148:targetgroup'
        for line in f:
            line = line.strip()
            if line.startswith('arn:aws:elasticloadbalancing:us-east-1:054037131148:targetgroup/'):
                tg_arn = line
                break
            
        # Read Load Balancer Arn starting with 'arn:aws:elasticloadbalancing:us-east-1:054037131148:loadbalancer'
        for line in f:
            line = line.strip()
            if line.startswith('arn:aws:elasticloadbalancing:us-east-1:054037131148:loadbalancer/'):
                load_balancer_arn = line
                break
        
        # Read RDS Identifier starting with 'stack-clixx-d'
        for line in f:
            line = line.strip()
            if line.startswith('stack-clixx-d'):
                rds_identifier = line
                break
            

    # Proceeding with deleting resources using the IDs gathered
    print("VPC ID:", vpc_id)
    print("Public Subnet IDs:", public_subnet_ids)
    print("Private Subnet IDs:", private_subnet_ids)
    print("Security Group ID:", security_group_id)
    print("Internet Gateway ID:", internet_gateway_id)
    print("NAT Gateway ID:", nat_gateway_id)
    print("Elastic IP ID:", eip_id)
    print("Route Table IDs:", route_table_ids)
    print("Target Group ARN:", tg_arn)
    print("Load Balancer ARN:", load_balancer_arn)
    print("RDS Identifier:", rds_identifier)
    
    
    
    cleanup_resources(vpc_id, public_subnet_ids, private_subnet_ids, security_group_id, internet_gateway_id, nat_gateway_id, eip_id, route_table_ids, tg_arn, load_balancer_arn,rds_identifier)
