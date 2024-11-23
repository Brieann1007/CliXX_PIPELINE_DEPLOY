#!/usr/bin/python

import boto3,botocore
import os
import time
from botocore.exceptions import ClientError

def delete_efs_and_mounts(mount_target_id, file_system_id):
    """Delete an EFS file system and all associated mount targets."""
    sts_client = boto3.client('sts')
    # Assume role for credentials
    assumed_role_object = sts_client.assume_role(
        RoleArn='arn:aws:iam::054037131148:role/Engineer',
        RoleSessionName='mysession'
    )
    credentials = assumed_role_object['Credentials']
    print(credentials)
    
    # Initialize the EFS client with assumed credentials
    efs = boto3.client('efs',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve file system ID and mount target IDs from SSM
        fs_id_param = ssm.get_parameter(Name='/clixx/efs')
        file_system_id = fs_id_param['Parameter']['Value']
        print(f"Retrieved EFS File System ID from SSM: {file_system_id}")
        
        mt_ids_param = ssm.get_parameter(Name='/clixx/mounttargetids')
        mount_target_ids = mt_ids_param['Parameter']['Value'].split(',')
        print("Retrieved Mount Target IDs:", mount_target_ids)

        # Delete each mount target individually
        for mount_target_id in mount_target_ids:
            try:
                efs.delete_mount_target(MountTargetId=mount_target_id)
                print(f"Deletion initiated for mount target {mount_target_id}")

                # Wait for the mount target to be deleted
                while True:
                    try:
                        efs.describe_mount_targets(MountTargetId=mount_target_id)
                        print(f"Waiting for mount target {mount_target_id} to be deleted...")
                        time.sleep(5)
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'MountTargetNotFound':
                            print(f"Mount target {mount_target_id} deleted.")
                            break
                        else:
                            print(f"Error while waiting for mount target deletion: {e}")
                            time.sleep(5)
            except ClientError as e:
                print(f"Error deleting mount target {mount_target_id}: {e}")

        # Delete the EFS file system after all mount targets are deleted
        efs.delete_file_system(FileSystemId=file_system_id)
        print(f"EFS File System {file_system_id} deletion initiated.")
        
        # Wait for the file system to be deleted
        while True:
            try:
                efs.describe_file_systems(FileSystemId=file_system_id)
                print("Waiting for EFS File System to be fully deleted...")
                time.sleep(10)
            except ClientError as e:
                if e.response['Error']['Code'] == 'FileSystemNotFound':
                    print(f"EFS File System {file_system_id} deleted.")
                    break
                else:
                    print(f"Error while waiting for EFS file system deletion: {e}")
                    time.sleep(10)
    except ClientError as e:
        print(f"Error retrieving mount targets or deleting EFS file system: {e}")

def delete_nat_gateway(nat_gateway_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Delete Nat Gateway ID from SSM Parameter Store
        natgw_id_param = ssm.get_parameter(Name='/clixx/natgateway_id')
        nat_gateway_id = natgw_id_param['Parameter']['Value']
        print('Retrieved nat gateway ID from SSM: %s' % (nat_gateway_id))
        # Finally, delete nat gateway
        ec2.delete_nat_gateway(NatGatewayId=nat_gateway_id)
        print('Deleted NAT Gateway with ID: %s' % (nat_gateway_id))
    
    except ClientError as e:
        print("Error: %s" % (e))
    
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
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve Elastic IP ID from SSM Parameter Store
        eip_id_param = ssm.get_parameter(Name='/clixx/eip_id')
        eip_id = eip_id_param['Parameter']['Value']
        print('Retrieved security group ID from SSM: %s' % (eip_id))
        # Finally, release the Elastic IP
        ec2.release_address(AllocationId=eip_id)
        print('Released Elastic IP with ID: %s' % (eip_id))
    
    except ClientError as e:
        print("Error: %s" % (e))
    
def delete_internet_gateway(ig_id, vpc_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve Internet Gateway ID from SSM Parameter Store
        igw_id_param = ssm.get_parameter(Name='/clixx/internetgateway_id')
        ig_id = igw_id_param['Parameter']['Value']
        print('Retrieved internet gateway ID from SSM: %s' % (ig_id))\
        # Retrieve VPC ID from SSM Parameter Store
        vpc_id_param = ssm.get_parameter(Name='/clixx/vpc_id')
        vpc_id = vpc_id_param['Parameter']['Value']
        print('Retrieved VPC ID from SSM: %s' % (vpc_id))
        # Finally, delete the Internet Gateway
        ec2.detach_internet_gateway(InternetGatewayId=ig_id, VpcId=vpc_id)
        ec2.delete_internet_gateway(InternetGatewayId=ig_id)
        print('Deleted Internet Gateway with ID: %s' % (ig_id))
    
    except ClientError as e:
        print("Error: %s" % (e))
    
def delete_subnet(subnet_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve subnet IDs from SSM Parameter Store
        public_subnet_ids_param = ssm.get_parameter(Name='/clixx/public_subnet_ids')
        private_subnet_ids_param = ssm.get_parameter(Name='/clixx/private_subnet_ids')

        public_subnet_ids = public_subnet_ids_param['Parameter']['Value'].split(',')
        private_subnet_ids = private_subnet_ids_param['Parameter']['Value'].split(',')
        print('Retrieved Public Subnet IDs: %s' % (public_subnet_ids))
        print('Retrieved Private Subnet IDs: %s' % (private_subnet_ids))

        # Delete public subnets
        for subnet_id in public_subnet_ids:
            ec2.delete_subnet(SubnetId=subnet_id)
            print(f'Deleted Public Subnet: {subnet_id}')

        # Delete private subnets
        for subnet_id in private_subnet_ids:
            ec2.delete_subnet(SubnetId=subnet_id)
            print(f'Deleted Private Subnet: {subnet_id}')
    
    except ClientError as e:
        print(f"Error: {e}")
        
def delete_security_group(security_group_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve Security Group ID from SSM Parameter Store
        sg_id_param = ssm.get_parameter(Name='/clixx/securitygroup_id')
        security_group_id = sg_id_param['Parameter']['Value']
        print('Retrieved security group ID from SSM: %s' % (security_group_id))
        # Finally, delete the Target Group
        ec2.delete_security_group(GroupId=security_group_id)
        print('Deleted Security Group with ARN: %s' % (security_group_id))
    
    except ClientError as e:
        print("Error: %s" % (e))
    
def delete_target_group(tg_arn):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    elbv2=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve Target Group ARN from SSM Parameter Store
        tg_arn_param = ssm.get_parameter(Name='/clixx/targetgroupARN')
        tg_arn = tg_arn_param['Parameter']['Value']
        print('Retrieved target group arn from SSM: %s' % (tg_arn))
        # Finally, delete the Target Group
        elbv2.delete_target_group(TargetGroupArn=tg_arn)
        print('Deleted Target Group with ID: %s' % (tg_arn))
    
    except ClientError as e:
        print("Error: %s" % (e))
    
def delete_route_table(route_table_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve Route Table ID from SSM Parameter Store
        rt_pub_id_param = ssm.get_parameter(Name='/clixx/publicroutetable')
        rt_priv_id_param = ssm.get_parameter(Name='/clixx/publicroutetable')
        
        pub_route_table_id = rt_pub_id_param['Parameter']['Value']
        priv_route_table_id = rt_priv_id_param['Parameter']['Value']
        print('Retrieved Public Route Table ID from SSM: %s' % (pub_route_table_id))
        print('Retrieved Private Route Table ID from SSM: %s' % (priv_route_table_id))
        # Finally, delete the Route Table
        for route_table_id in pub_route_table_id:
            ec2.delete_route_table(RouteTableId=route_table_id)
            print('Deleted Public Route Table with ID: %s' % (route_table_id))

        for route_table_id in priv_route_table_id:
            ec2.delete_route_table(RouteTableId=route_table_id)
            print('Deleted Private Route Table with ID: %s' % (route_table_id))
    
    except ClientError as e:
        print("Error: %s" % (e))
    
def delete_load_balancer(load_balancer_arn):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    elbv2=boto3.client('elbv2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve Load Balancer ARN from SSM Parameter Store
        lb_arn_param = ssm.get_parameter(Name='/clixx/LoadBalancerARN')
        load_balancer_arn = lb_arn_param['Parameter']['Value']
        print('Retrieved load balancer arn from SSM: %s' % (load_balancer_arn))
        # Finally, delete the Load Balancer
        elbv2.delete_load_balancer(LoadBalancerArn=load_balancer_arn)
        print("Deleted Load Balancer: %s" % (load_balancer_arn))
    
    except ClientError as e:
        print("Error: %s" % (e))
     
def delete_db_instance(rds_identifier,db_subnet_group_name):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    rds=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve RDS Identifier from SSM Parameter Store
        rds_identifier_param = ssm.get_parameter(Name='/clixx/db_instance_identifier')
        rds_identifier = rds_identifier_param['Parameter']['Value']
        print('Retrieved RDS identifier from SSM:', rds_identifier)
        
        # Delete the RDS instance
        rds.delete_db_instance(DBInstanceIdentifier=rds_identifier, SkipFinalSnapshot=True)
        print("Deletion initiated for RDS instance:", rds_identifier)

        # Wait for the RDS instance to be deleted
        print("Waiting for RDS instance to be fully deleted...")
        while True:
            try:
                rds.describe_db_instances(DBInstanceIdentifier=rds_identifier)
                print("RDS instance is still being deleted...")
                time.sleep(10)
            except ClientError as e:
                if e.response['Error']['Code'] == 'DBInstanceNotFound':
                    print("Deleted RDS Instance:", rds_identifier)
                    break
                else:
                    print("Error while waiting for RDS deletion:", e)
                    time.sleep(10)
        # Retrieve db_subnet_group_name from SSM Parameter Store
        db_subnet_group_param = ssm.get_parameter(Name='/clixx/db_subnet_group_name')
        db_subnet_group_name = db_subnet_group_param['Parameter']['Value']
        print(f"Retrieved DB Subnet Group Name from SSM: {db_subnet_group_name}")

        # Delete the DB Subnet Group
        print(f"Deleting DB Subnet Group: {db_subnet_group_name}")
        rds.delete_db_subnet_group(DBSubnetGroupName=db_subnet_group_name)
        print(f"DB Subnet Group {db_subnet_group_name} successfully deleted.")
        
    except ClientError as e:
        print("Error:", e)
        
def delete_launch_template(lt_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ssm_client = boto3.client('ssm',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ec2 = boto3.client('ec2', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve the Launch Template name from SSM Parameter Store
        parameter_name = '/clixx/LaunchTemplateID'
        response = ssm_client.get_parameter(Name=parameter_name)
        lt_id = response['Parameter']['Value']
        print(f"Retrieved Launch Template Name Name from SSM: {lt_id}")

        # Delete the launch template
        ec2.delete_launch_template(
                LaunchTemplateId=lt_id
        )
        print(f"Launch Template '{lt_id}' deleted successfully.")
        return True

    except ClientError as error:
        print(f"An error occurred: {error}")
        return False

def delete_auto_scaling_group(asg_name):
    try:
        # Initialize the STS client
        sts_client = boto3.client('sts')
        # Assume the specified IAM role
        assumed_role_object = sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer',RoleSessionName='mysession')
        credentials = assumed_role_object['Credentials']
        # Initialize the SSM and Auto Scaling clients with assumed role credentials
        ssm_client = boto3.client('ssm',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
        autoscaling_client = boto3.client('autoscaling',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
        
        # Retrieve the Auto Scaling group name from SSM Parameter Store
        parameter_name = '/clixx/AutoScalingGroups'
        response = ssm_client.get_parameter(Name=parameter_name)
        asg_name = response['Parameter']['Value']
        print(f"Retrieved Auto Scaling Group Name from SSM: {asg_name}")
        
        # Delete the Auto Scaling group and its instances
        autoscaling_client.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            ForceDelete=True  # Ensures all instances are terminated
        )
        print(f"Deleted Auto Scaling Group: {asg_name}")
    
    except ClientError as e:
        print(f"An error occurred: {e}")

def delete_route53_record(hosted_zone_id, record_name):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    # Initialize the Route 53 client
    route53_client = boto3.client('route53',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    # Define the change batch request to delete the specified record
    change_batch = {
        'Changes': [
            {
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'A',
                    # Specify the TTL and ResourceRecords as they exist
                    'TTL': 300,  # Replace with the actual TTL of the record
                    'ResourceRecords': [
                        {'Value': '192.0.2.1'},  # Replace with the actual value(s) of the record
                    ],
                }
            },
        ]
    }
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve VPC ID from SSM Parameter Store
        hosted_zone_id_param = ssm.get_parameter(Name='/clixx/hostedzoneid')
        hosted_zone_id = hosted_zone_id_param['Parameter']['Value']
        print('Retrieved Hosted Zone ID from SSM: %s' % (hosted_zone_id))
        # Submit the change batch request
        route53_client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch=change_batch
        )
    except ClientError as e:
        print("Error: %s" % (e))
                        
def delete_vpc(vpc_id):
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'],region_name='us-east-1')
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        # Retrieve VPC ID from SSM Parameter Store
        vpc_id_param = ssm.get_parameter(Name='/clixx/vpc_id')
        vpc_id = vpc_id_param['Parameter']['Value']
        print('Retrieved VPC ID from SSM: %s' % (vpc_id))
        # Finally, delete the VPC
        ec2.delete_vpc(VpcId=vpc_id)
        print('Deleted VPC with ID: %s.' % (vpc_id))
    
    except ClientError as e:
        print("Error: %s" % (e))

def get_from_ssm(parameter_name):
    """Retrieve a parameter from AWS SSM Parameter Store."""
    ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'], region_name='us-east-1')
    try:
        response = ssm.get_parameter(Name=parameter_name)
        return response['Parameter']['Value']
    except ClientError as e:
        if e.response['Error']['Code'] == 'ParameterNotFound':
            print(f"SSM Parameter '{parameter_name}' not found, skipping.")
        else:
            print(f"Error retrieving parameter {parameter_name} from SSM: {e}")
        return None

def cleanup_resources(
    vpc_id, public_subnet_ids, private_subnet_ids, security_group_id, 
    mount_target_id, file_system_id, internet_gateway_id, nat_gateway_id, 
    eip_id, pub_route_table_ids, priv_route_table_ids, tg_arn, 
    load_balancer_arn, rds_identifier, db_subnet_group_name, asg_name, lt_id, hosted_zone_id, record_name
):
    # Delete NAT Gateway and associated resources
    delete_efs_and_mounts(mount_target_id, file_system_id)
    delete_nat_gateway(nat_gateway_id)
    delete_load_balancer(load_balancer_arn)
    delete_db_instance(rds_identifier, db_subnet_group_name)
    release_address(eip_id)
    delete_launch_template(lt_id)
    delete_auto_scaling_group(asg_name)
    time.sleep(120)
    # Unmap public IPs and delete subnets
    for public_subnet_id in public_subnet_ids:
        unmap_public_ip(public_subnet_id)
    for subnet_id in public_subnet_ids + private_subnet_ids:
        delete_subnet(subnet_id)

    # Delete security groups and internet gateway
    delete_security_group(security_group_id)
    delete_internet_gateway(internet_gateway_id, vpc_id)
    delete_route53_record(hosted_zone_id, record_name)
    # Delete route tables
    for route_table_id in pub_route_table_ids + priv_route_table_ids:
        delete_route_table(route_table_id)
    
    delete_target_group(tg_arn)

    # Wait before deleting VPC to ensure all dependencies are removed

    delete_vpc(vpc_id)
    
if __name__=="__main__":
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)

    # Define IDs for the resources to delete (replace these with actual retrieval from SSM)
    public_subnet_ids = []
    private_subnet_ids = []
    security_group_id = None
    mount_target_id = []
    file_system_id = None
    internet_gateway_id = None
    nat_gateway_id = None
    eip_id = None
    pub_route_table_ids = []
    priv_route_table_ids = []
    tg_arn = None
    vpc_id = None
    load_balancer_arn = None
    rds_identifier = None
    db_subnet_group_name = None
    asg_name = None
    lt_id = None
    hosted_zone_id = None
    record_name = None

    # Print resource IDs and proceed with deletion
    print("Deleting resources with the following IDs:")
    print("VPC ID:", vpc_id)
    print("Public Subnet IDs:", public_subnet_ids)
    print("Private Subnet IDs:", private_subnet_ids)
    print("Security Group ID:", security_group_id)
    print("Mount Target IDs:", mount_target_id)
    print("File System ID:", file_system_id)
    print("Internet Gateway ID:", internet_gateway_id)
    print("NAT Gateway ID:", nat_gateway_id)
    print("Elastic IP ID:", eip_id)
    print("Public Route Table IDs:", pub_route_table_ids)
    print("Private Route Table IDs:", priv_route_table_ids)
    print("Target Group ARN:", tg_arn)
    print("Load Balancer ARN:", load_balancer_arn)
    print("RDS Identifier:", rds_identifier)
    print("DB Subnet Group Name:", db_subnet_group_name)
    print("Autoscaling Group Name:", asg_name)
    print("Launch Template Name:", lt_id)
    print("Hosted Zone ID:", hosted_zone_id)
    print("Route 53 Record Name:", record_name)
    
    cleanup_resources(
        vpc_id, public_subnet_ids, private_subnet_ids, security_group_id,
        mount_target_id, file_system_id, internet_gateway_id, nat_gateway_id,
        eip_id, pub_route_table_ids, priv_route_table_ids, tg_arn,
        load_balancer_arn, rds_identifier, db_subnet_group_name, asg_name, lt_id, hosted_zone_id, record_name
    )