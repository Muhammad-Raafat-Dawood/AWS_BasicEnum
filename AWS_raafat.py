import os

# Get AWS access key ID, secret access key, and session token from environment variables
aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
aws_session_token = os.environ.get('AWS_SESSION_TOKEN')
aws_defaulr_region = os.environ.get('AWS_DEFAULT_REGION')

# Define AWS CLI commands to run
caller_identity = f'aws sts get-caller-identity --output json'
iam_users = f'aws iam list-users --output json'
iam_groups = f'aws iam list-groups'
iam_rols = f'aws iam list-roles'
iam_policies = f'aws iam list-policies'
iam_instance_profiles = f'aws iam list-instance-profiles'
secretmanager_secrets = f'aws secretsmanager list-secrets'
kms_keys = f'aws kms list-keys'
ec2_instances = f'aws ec2 describe-instances  --output json'
ec2_profile_associations_command = f'aws ec2 describe-iam-instance-profile-associations'
ec2_VPCs_command = f'aws ec2 describe-vpcs --output json'
ec2_VPCs_peering_connections_command = f'aws ec2 describe-vpc-peering-connections'
ec2_subnets_command = f'aws ec2 describe-subnets  --output json'
ec2_route_table_command = f'aws ec2 describe-route-tables  --output json'
ec2_network_acls_command = f'aws ec2 describe-network-acls  --output json'
ec2_volumes = f'aws ec2 describe-volumes'
ec2_snapshots = f'aws ec2 describe-snapshots --owner-ids self'
s3_command = f'aws s3api list-buckets --output json'
lambda_functions = f'aws lambda list-functions'
lambda_layers = f'aws lambda list-layers'
apigateway_rest_apis = f'aws apigateway get-rest-apis'
apigateway_api_keys = f'aws apigateway get-api-keys --include-values'
dynamodb_tables = f'aws dynamodb list-tables'
dynamodb_backups = f'aws dynamodb list-backups'
dynamodb_global_tables= f'aws dynamodb list-global-tables'
dynamodb_exports = f'aws dynamodb list-exports'
dynamodb_endpoints = f'aws dynamodb describe-endpoints'
ecr_repositories = f'aws ecr describe-repositories'
ecs_clusters = f'aws ecs list-clusters'
eks_clusters = f'aws eks list-clusters'
rds_db_clusters = f'aws rds describe-db-clusters'
rds_db_instances = f'aws rds describe-db-instances'
rds_db_subnet_groups = f'aws rds describe-db-subnet-groups'
rds_db_security_groups = f'aws rds describe-db-security-groups'
rds_db_proxies = f'aws rds describe-db-proxies'
aws_MetaData = f'TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/'
aws_UserData = f'TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/user-data/'


# Define a function to run an AWS CLI command and return the output
def run_command(command):
    output = os.popen(command).read()
    if "An error occurred" in output:
        pass
    else:
        return output

# Run the AWS CLI commands and print the output

print('Caller Identity:')
print(run_command(caller_identity))

print('IAM Users:')
print(run_command(iam_users))

print('IAM Groups:')
print(run_command(iam_groups))

print('IAM Roles:')
print(run_command(iam_rols))

print('IAM Instance instance_profiles:')
print(run_command(iam_instance_profiles))

print('SecretManager Secrets:')
print(run_command(secretmanager_secrets))

print('KMS keys:')
print(run_command(kms_keys))

print('IAM Policies:')
print(run_command(iam_policies))

print('EC2 Instances:')
print(run_command(ec2_instances))

print('EC2 Instances Profile associations:')
print(run_command(ec2_profile_associations_command))

print('EC2 VPCs:')
print(run_command(ec2_VPCs_command))

print('EC2 VPCs Peering connections:')
print(run_command(ec2_VPCs_peering_connections_command))

print('EC2 Subnets:')
print(run_command(ec2_subnets_command))

print('EC2 Routing tables:')
print(run_command(ec2_route_table_command))

print('EC2 Network Access Lists:')
print(run_command(ec2_network_acls_command))

print('EC2 EBS Volumes:')
print(run_command(ec2_volumes))

print('EC2 EBS Snapshots:')
print(run_command(ec2_snapshots))

print('S3 Buckets:')
print(run_command(s3_command))

print('Lambda Functions:')
print(run_command(lambda_functions))

print('Lambda Layers:')
print(run_command(lambda_layers))

print('APIGateway Rest APIs:')
print(run_command(apigateway_rest_apis))

print('APIGateway API Keys :')
print(run_command(apigateway_api_keys))

print('Dynamodb Tables :')
print(run_command(dynamodb_tables))

print('Dynamodb Backups :')
print(run_command(dynamodb_backups))

print('Dynamodb Global Tables :')
print(run_command(dynamodb_global_tables))

print('Dynamodb Exports :')
print(run_command(dynamodb_exports))

print('Dynamodb Endpoints :')
print(run_command(dynamodb_endpoints))

print('ECR Repositories :')
print(run_command(ecr_repositories))

print('ECS Clusters :')
print(run_command(ecs_clusters))

print('EkS Clusters :')
print(run_command(ecs_clusters))

print('RDS DB Clusters :')
print(run_command(rds_db_clusters))

print('RDS DB Instances :')
print(run_command(rds_db_instances))

print('RDS DB Subnet Groups :')
print(run_command(rds_db_subnet_groups))

print('RDS DB Security Groups :')
print(run_command(rds_db_security_groups))

print('RDS DB Proxies:')
print(run_command(rds_db_proxies))

print('AWS Meta Data:')
print(run_command(aws_MetaData))

print('AWS User Data:')
print(run_command(aws_UserData))
