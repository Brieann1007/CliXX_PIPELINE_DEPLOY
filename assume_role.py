#!/usr/bin/python
import boto3,botocore
from botocore.exceptions import ClientError
import time
import base64
import os

vpc_txt_loc='/src/github.com/Brieann1007/CliXX_PIPELINE_DEPLOY/vpc.txt'
 

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

        # Save the VPC ID to SSM Parameter Store
        ssm = boto3.client('ssm', aws_access_key_id=credentials['AccessKeyId'],
                           aws_secret_access_key=credentials['SecretAccessKey'],
                           aws_session_token=credentials['SessionToken'], region_name='us-east-1')
        ssm.put_parameter(
            Name='/clixx/vpc_id',
            Value=vpc_id,
            Type='String',
            Overwrite=True
        )
        print('VPC ID: %s saved to SSM Parameter Store under "/clixx/vpc_id"' % (vpc_id))
        
        return vpc_id
    
    except ClientError as e:
        print(e)
        

if __name__=="__main__":
    sts_client=boto3.client('sts')
    #Calling the assume_role function
    assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')
    credentials=assumed_role_object['Credentials']
    print(credentials)
    vpc_id = create_vpc(service="ec2")

    
