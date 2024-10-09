#!/usr/bin/python

import boto3,botocore
from botocore.exceptions import ClientError

sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::054037131148:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)

# s3=boto3.client('s3',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
# response = s3.list_buckets(
#     MaxBuckets=123)

# print(response)
ec2 = boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
response = ec2.describe_vpcs()
vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')
print(vpc_id)
try:
    ec2=boto3.client('ec2',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
    response = ec2.create_security_group(
        Description='stack_web_dmz_cli',
        GroupName='stack_web_dmz_cli',
        VpcId='vpc-0f6c3540fa540a07b'
        )
    
    print(response)
    security_group_id = response['GroupId']
    print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id))

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
except ClientError as e:
    print(e)
efs=boto3.client('efs',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])
response=efs.describe_file_systems()
print(response)
response=efs.create_file_system(
    CreationToken='',
    PerformanceMode='generalPurpose',
    Encrypted=True,
    KmsKeyId='15a7670d-cdec-4cb6-b89a-8e6a0d492c13',
    ThroughputMode='bursting',
    ProvisionedThroughputInMibps=123.0,
    AvailabilityZoneName='Regional',
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
