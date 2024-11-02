#!/usr/bin/python

import boto3,botocore
import os
import time
from botocore.exceptions import ClientError


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
        # Deleting the parameter from SSM
        ssm.delete_parameter(Name='/clixx/vpc_id')
        print('Deleted VPC ID from SSM Parameter Store.')
    
    except ClientError as e:
        print("Error: %s" % (e))
    

if __name__=="__main__":
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)

    vpc_id = None

    

            

    # Proceeding with deleting resources using the IDs gathered
    print("VPC ID:", vpc_id)
    
    delete_vpc(vpc_id)