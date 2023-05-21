
provider "aws" {
  region = "ap-south-1"
  #profile = "infra"
}

# Get current aws account id
data "aws_caller_identity" "current_account" {}

# Get current aws region
data "aws_region" "current_region" {}

# Create IAM Role for EC2 Instance profile with SSM Full Access
data "aws_iam_policy" "ssm_full_access" {
  name = "AmazonSSMFullAccess"
}

data "aws_iam_policy" "ec2_full_access" {
  name = "AmazonEC2FullAccess"
}

resource "aws_iam_role" "ec2_instance_profile_role" {
  name = "TerraformIAMInstanceProfileRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "InstanceProfileSid"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  managed_policy_arns = [data.aws_iam_policy.ssm_full_access.arn]

  tags = {
    Name = "TerraformIAMInstanceProfileRole"
  }
}

# ============== Get latest Amazon Linux 2 AMI ==============
data "aws_ami" "amzn_linux_2" {
  most_recent = true

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["amazon"]
}

output "ami_id" {
  value       = data.aws_ami.amzn_linux_2.id
  description = "AMI ID"
}

# ============= Get 'default' vpc in the region =============
data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from public"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # This is not good to open ssh connection from entire world. This is for illustration purpose only
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "allow_ssh"
  }
}

# ================ Create the Target EC2 instance ================

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.ec2_instance_profile_role.name
}

resource "aws_instance" "critical_app" {
  ami                         = data.aws_ami.amzn_linux_2.id
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.id
  instance_type               = "t2.micro"
  vpc_security_group_ids      = [aws_security_group.allow_ssh.id]
  root_block_device {
    volume_size = 8
    volume_type = "gp3"
  }

  user_data = <<EOF
    #!/usr/bin/env bash
    sudo useradd -p $(openssl passwd -1 redhat) paul
    # by default user is locked
    usermod -L paul
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    systemctl restart sshd
    yum update
    yum install docker -y
    systemctl enable --now docker
    docker pull ubuntu:14.04
    
    EOF

  tags = {
    # This value should NOT be changed. It is used in get_instance_id.py to retrieve instance-id using tagName
    Name = "critical_app"
  }
}


# ===================== Create Lambda function for User Locking =====================
data "archive_file" "lock_user" {
  type = "zip"

  source_file = "${path.module}/lock_user.py"
  output_path = "${path.module}/LockUser.zip"
}


resource "aws_iam_role" "lock_user_lambda_role" {
  name = "LockUserLambdaRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "Lambda4LockUser"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
  managed_policy_arns = [
    data.aws_iam_policy.ssm_full_access.arn,
    data.aws_iam_policy.ec2_full_access.arn,
    aws_iam_policy.lock_user_lambda_cw_logging.arn
  ]

  tags = {
    Name = "LockUserLambdaRole"
  }
}

resource "aws_iam_policy" "lock_user_lambda_cw_logging" {
  name = "lock_user_lambda_cw_logging"
  # path        = "/"
  description = "IAM policy for logging from Locak User lambda function"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:log-group:/aws/lambda/LockUsers:*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances"
            ],
            "Resource": [
                "${aws_instance.critical_app.arn}"
            ]
        }
    ]
  }
EOF
}


resource "aws_cloudwatch_log_group" "lock_user_lambda_log" {
  name              = "/aws/lambda/LockUsers"
  retention_in_days = 7
}

resource "aws_lambda_function" "lock_user" {
  filename         = "${path.module}/LockUser.zip"
  function_name    = "LockUserLambda"
  handler          = "lock_user.lock"
  role             = aws_iam_role.lock_user_lambda_role.arn
  runtime          = "python3.10"
  source_code_hash = data.archive_file.lock_user.output_base64sha256


  depends_on = [
    # aws_iam_role_policy_attachment.lock_user_lambda_logs,
    aws_cloudwatch_log_group.lock_user_lambda_log,
  ]
}


# ===================== Create Lambda function to Unlock User =====================
data "archive_file" "unlock_user" {
  type = "zip"

  source_file = "${path.module}/unlock_user.py"
  output_path = "${path.module}/UnlockUser.zip"
}


resource "aws_iam_role" "unlock_user_lambda_role" {
  name = "UnlockUserLambdaRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "Unlambda4LockUser"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
  managed_policy_arns = [
    data.aws_iam_policy.ssm_full_access.arn,
    data.aws_iam_policy.ec2_full_access.arn,
    aws_iam_policy.unlock_user_lambda_cw_logging.arn
  ]

  tags = {
    Name = "UnlockUserLambdaRole"
  }
}

resource "aws_iam_policy" "unlock_user_lambda_cw_logging" {
  name = "unlock_user_lambda_cw_logging"
  # path        = "/"
  description = "IAM policy for logging from Unlock User lambda function"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:log-group:/aws/lambda/UnlockUsers:*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances"
            ],
            "Resource": [
                "${aws_instance.critical_app.arn}"
            ]
        }
    ]
  }
EOF
}


resource "aws_cloudwatch_log_group" "unlock_user_lambda_log" {
  name              = "/aws/lambda/UnlockUsers"
  retention_in_days = 7
}

resource "aws_lambda_function" "unlock_user" {
  filename         = "${path.module}/UnlockUser.zip"
  function_name    = "UnlockUserLambda"
  handler          = "unlock_user.unlock"
  role             = aws_iam_role.unlock_user_lambda_role.arn
  runtime          = "python3.10"
  source_code_hash = data.archive_file.unlock_user.output_base64sha256


  depends_on = [
    aws_cloudwatch_log_group.unlock_user_lambda_log,
  ]
}

# ===================== Create Lambda function to Run Docker Containers =====================

data "archive_file" "run_containers" {
  type = "zip"

  source_file = "${path.module}/run_containers.py"
  output_path = "${path.module}/run_containers.zip"
}


resource "aws_iam_role" "run_containers_lambda_role" {
  name = "RunContainersLambdaRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "Lambda2RunContainers"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
  managed_policy_arns = [
    data.aws_iam_policy.ssm_full_access.arn,
    data.aws_iam_policy.ec2_full_access.arn,
    aws_iam_policy.run_containers_lambda_cw_logging.arn
  ]

  tags = {
    Name = "RunContainersLambdaRole"
  }
}

resource "aws_iam_policy" "run_containers_lambda_cw_logging" {
  name = "run_containers_lambda_cw_logging"
  # path        = "/"
  description = "IAM policy for logging from Run Containers Lambda Function"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:log-group:/aws/lambda/RunContainers:*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances"
            ],
            "Resource": [
                "${aws_instance.critical_app.arn}"
            ]
        }
    ]
  }
EOF
}


resource "aws_cloudwatch_log_group" "run_containers_lambda_log" {
  name              = "/aws/lambda/RunContainers"
  retention_in_days = 7
}

resource "aws_lambda_function" "run_containers" {
  filename         = "${path.module}/run_containers.zip"
  function_name    = "RunContainersLambda"
  handler          = "run_containers.docker_container"
  role             = aws_iam_role.run_containers_lambda_role.arn
  runtime          = "python3.10"
  source_code_hash = data.archive_file.run_containers.output_base64sha256


  depends_on = [
    aws_cloudwatch_log_group.run_containers_lambda_log,
  ]
}

# ===================== Create Lambda function to Destroy Docker Containers =====================

data "archive_file" "destroy_containers" {
  type = "zip"

  source_file = "${path.module}/destroy_containers.py"
  output_path = "${path.module}/destroy_containers.zip"
}


resource "aws_iam_role" "destroy_containers_lambda_role" {
  name = "DestroyContainersLambdaRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "Lambda2DestroyContainers"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
  managed_policy_arns = [
    data.aws_iam_policy.ssm_full_access.arn,
    data.aws_iam_policy.ec2_full_access.arn,
    aws_iam_policy.run_containers_lambda_cw_logging.arn
  ]

  tags = {
    Name = "DestroyContainersLambdaRole"
  }
}

resource "aws_iam_policy" "destroy_containers_lambda_cw_logging" {
  name = "destroy_containers_lambda_cw_logging"
  # path        = "/"
  description = "IAM policy for logging from Destroy Containers Lambda Function"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:log-group:/aws/lambda/DestroyContainers:*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances"
            ],
            "Resource": [
                "${aws_instance.critical_app.arn}"
            ]
        }
    ]
  }
EOF
}


resource "aws_cloudwatch_log_group" "destroy_containers_lambda_log" {
  name              = "/aws/lambda/DestroyContainers"
  retention_in_days = 7
}

resource "aws_lambda_function" "destroy_containers" {
  filename         = "${path.module}/destroy_containers.zip"
  function_name    = "DestroyContainersLambda"
  handler          = "destroy_containers.docker_container"
  role             = aws_iam_role.destroy_containers_lambda_role.arn
  runtime          = "python3.10"
  source_code_hash = data.archive_file.destroy_containers.output_base64sha256


  depends_on = [
    aws_cloudwatch_log_group.destroy_containers_lambda_log,
  ]
}

# ================= Create a REST API Gateway =================

resource "aws_api_gateway_rest_api" "serverless_lambda_apigw" {
  name = "serverless_lambda_apigw"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# ================= API Resource to Lock User =================

resource "aws_lambda_permission" "lock_lambda_apigw" {
  statement_id  = "AllowExecutionFromAPIGatewayToLambdaFunctionToLockUser"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lock_user.function_name
  principal     = "apigateway.amazonaws.com"

  # More: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html
  source_arn = "arn:aws:execute-api:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:${aws_api_gateway_rest_api.serverless_lambda_apigw.id}/*/${aws_api_gateway_method.lock_lambda_apigw.http_method}${aws_api_gateway_resource.lock_lambda_apigw.path}/*"

  # The /* part allows invocation from any stage, method and resource path
  # within API Gateway.
  # source_arn = "${aws_api_gateway_rest_api.serverless_lambda_apigw.execution_arn}/*"
}

resource "aws_api_gateway_resource" "lock_lambda_apigw" {
  parent_id   = aws_api_gateway_rest_api.serverless_lambda_apigw.root_resource_id
  path_part   = "lock"
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
}

resource "aws_api_gateway_resource" "lock_path_paramter" {
  parent_id   = aws_api_gateway_resource.lock_lambda_apigw.id
  path_part   = "{user}"
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
}

resource "aws_api_gateway_method" "lock_lambda_apigw" {
  authorization = "NONE"
  http_method   = "GET"
  resource_id   = aws_api_gateway_resource.lock_path_paramter.id
  rest_api_id   = aws_api_gateway_rest_api.serverless_lambda_apigw.id

  request_parameters = {
    "method.request.path.user" = true
  }
}

resource "aws_api_gateway_integration" "lock_lambda_apigw" {
  http_method             = aws_api_gateway_method.lock_lambda_apigw.http_method
  resource_id             = aws_api_gateway_resource.lock_path_paramter.id
  rest_api_id             = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.lock_user.invoke_arn
}

resource "aws_api_gateway_method_response" "lock_lambda_apigw_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  resource_id = aws_api_gateway_resource.lock_path_paramter.id
  http_method = aws_api_gateway_method.lock_lambda_apigw.http_method
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }

  depends_on = [aws_api_gateway_method.lock_lambda_apigw]
}

resource "aws_api_gateway_integration_response" "lock_lambda_apigw_response" {
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  resource_id = aws_api_gateway_resource.lock_path_paramter.id
  http_method = aws_api_gateway_method.lock_lambda_apigw.http_method
  status_code = aws_api_gateway_method_response.lock_lambda_apigw_method_response_200.status_code

  # response_templates = {
  #   "application/json" = ""
  # }

  depends_on = [aws_api_gateway_integration.lock_lambda_apigw]
}

# ================= API Resource to Unlock User =================

resource "aws_lambda_permission" "unlock_lambda_apigw" {
  statement_id  = "AllowExecutionFromAPIGatewayToUnlockUserLambdaFunction"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.unlock_user.function_name
  principal     = "apigateway.amazonaws.com"

  # More: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html
  source_arn = "arn:aws:execute-api:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:${aws_api_gateway_rest_api.serverless_lambda_apigw.id}/*/${aws_api_gateway_method.unlock_lambda_apigw.http_method}${aws_api_gateway_resource.unlock_lambda_apigw.path}/*"
}

resource "aws_api_gateway_resource" "unlock_lambda_apigw" {
  parent_id   = aws_api_gateway_rest_api.serverless_lambda_apigw.root_resource_id
  path_part   = "unlock"
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
}

resource "aws_api_gateway_resource" "unlock_path_paramter" {
  parent_id   = aws_api_gateway_resource.unlock_lambda_apigw.id
  path_part   = "{user}"
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
}

resource "aws_api_gateway_method" "unlock_lambda_apigw" {
  authorization = "NONE"
  http_method   = "GET"
  resource_id   = aws_api_gateway_resource.unlock_path_paramter.id
  rest_api_id   = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  request_parameters = {
    "method.request.path.user" = true
  }
}

resource "aws_api_gateway_integration" "unlock_lambda_apigw" {
  http_method             = aws_api_gateway_method.unlock_lambda_apigw.http_method
  resource_id             = aws_api_gateway_resource.unlock_path_paramter.id
  rest_api_id             = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.unlock_user.invoke_arn
}


resource "aws_api_gateway_method_response" "unlock_lambda_apigw_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  resource_id = aws_api_gateway_resource.unlock_path_paramter.id
  http_method = aws_api_gateway_method.unlock_lambda_apigw.http_method
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }

  depends_on = [aws_api_gateway_method.unlock_lambda_apigw]
}

resource "aws_api_gateway_integration_response" "unlock_lambda_apigw_response" {
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  resource_id = aws_api_gateway_resource.unlock_path_paramter.id
  http_method = aws_api_gateway_method.unlock_lambda_apigw.http_method
  status_code = aws_api_gateway_method_response.unlock_lambda_apigw_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.unlock_lambda_apigw]
}

# ================= API Resource to Run Docker Containers =================

resource "aws_lambda_permission" "run_containers_lambda_apigw" {
  statement_id  = "AllowExecutionFromAPIGatewayToRunDockerContainersUsingLambdaFunction"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.run_containers.function_name
  principal     = "apigateway.amazonaws.com"

  # More: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html
  source_arn = "arn:aws:execute-api:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:${aws_api_gateway_rest_api.serverless_lambda_apigw.id}/*/${aws_api_gateway_method.run_containers_lambda_apigw.http_method}${aws_api_gateway_resource.run_containers_lambda_apigw.path}"
}

resource "aws_api_gateway_resource" "run_containers_lambda_apigw" {
  parent_id   = aws_api_gateway_rest_api.serverless_lambda_apigw.root_resource_id
  path_part   = "container"
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
}

# resource "aws_api_gateway_resource" "run_containers_path_paramter" {
#   parent_id   = aws_api_gateway_resource.run_containers_lambda_apigw.id
#   path_part   = "{count}"
#   rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
# }

resource "aws_api_gateway_method" "run_containers_lambda_apigw" {
  authorization = "NONE"
  http_method   = "GET"
  resource_id   = aws_api_gateway_resource.run_containers_lambda_apigw.id
  rest_api_id   = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  # request_parameters = {
  #   "method.request.path.count" = true
  # }
}

resource "aws_api_gateway_integration" "run_containers_lambda_apigw" {
  http_method             = aws_api_gateway_method.run_containers_lambda_apigw.http_method
  resource_id             = aws_api_gateway_resource.run_containers_lambda_apigw.id
  rest_api_id             = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.run_containers.invoke_arn
}


resource "aws_api_gateway_method_response" "run_containers_lambda_apigw_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  resource_id = aws_api_gateway_resource.run_containers_lambda_apigw.id
  http_method = aws_api_gateway_method.run_containers_lambda_apigw.http_method
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }

  depends_on = [aws_api_gateway_method.run_containers_lambda_apigw]
}

resource "aws_api_gateway_integration_response" "run_containers_lambda_apigw_response" {
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  resource_id = aws_api_gateway_resource.run_containers_lambda_apigw.id
  http_method = aws_api_gateway_method.run_containers_lambda_apigw.http_method
  status_code = aws_api_gateway_method_response.run_containers_lambda_apigw_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.run_containers_lambda_apigw]
}

# ================= API Resource to Destroy Docker Containers =================

resource "aws_lambda_permission" "destroy_containers_lambda_apigw" {
  statement_id  = "AllowExecutionFromAPIGatewayToDestroyDockerContainersUsingLambdaFunction"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.destroy_containers.function_name
  principal     = "apigateway.amazonaws.com"

  # More: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html
  source_arn = "arn:aws:execute-api:${data.aws_region.current_region.name}:${data.aws_caller_identity.current_account.account_id}:${aws_api_gateway_rest_api.serverless_lambda_apigw.id}/*/${aws_api_gateway_method.destroy_containers_lambda_apigw.http_method}${aws_api_gateway_resource.destroy_containers_lambda_apigw.path}"
}

resource "aws_api_gateway_resource" "destroy_containers_lambda_apigw" {
  parent_id   = aws_api_gateway_rest_api.serverless_lambda_apigw.root_resource_id
  path_part   = "destroycontainer"
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
}

resource "aws_api_gateway_method" "destroy_containers_lambda_apigw" {
  authorization = "NONE"
  http_method   = "GET"
  resource_id   = aws_api_gateway_resource.destroy_containers_lambda_apigw.id
  rest_api_id   = aws_api_gateway_rest_api.serverless_lambda_apigw.id
}

resource "aws_api_gateway_integration" "destroy_containers_lambda_apigw" {
  http_method             = aws_api_gateway_method.destroy_containers_lambda_apigw.http_method
  resource_id             = aws_api_gateway_resource.destroy_containers_lambda_apigw.id
  rest_api_id             = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.destroy_containers.invoke_arn
}


resource "aws_api_gateway_method_response" "destroy_containers_lambda_apigw_method_response_200" {
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  resource_id = aws_api_gateway_resource.destroy_containers_lambda_apigw.id
  http_method = aws_api_gateway_method.destroy_containers_lambda_apigw.http_method
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }

  depends_on = [aws_api_gateway_method.run_containers_lambda_apigw]
}

resource "aws_api_gateway_integration_response" "destroy_containers_lambda_apigw_response" {
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  resource_id = aws_api_gateway_resource.destroy_containers_lambda_apigw.id
  http_method = aws_api_gateway_method.destroy_containers_lambda_apigw.http_method
  status_code = aws_api_gateway_method_response.destroy_containers_lambda_apigw_method_response_200.status_code

  depends_on = [aws_api_gateway_integration.destroy_containers_lambda_apigw]
}

resource "aws_api_gateway_deployment" "test" {
  rest_api_id = aws_api_gateway_rest_api.serverless_lambda_apigw.id

  triggers = {
    # NOTE: The configuration below will satisfy ordering considerations,
    #       but not pick up all future REST API changes. More advanced patterns
    #       are possible, such as using the filesha1() function against the
    #       Terraform configuration file(s) or removing the .id references to
    #       calculate a hash against whole resources. Be aware that using whole
    #       resources will show a difference after the initial implementation.
    #       It will stabilize to only change when resources change afterwards.
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.lock_lambda_apigw.id,
      aws_api_gateway_resource.lock_path_paramter.id,
      aws_api_gateway_method.lock_lambda_apigw.id,
      aws_api_gateway_integration.lock_lambda_apigw.id,
      aws_api_gateway_method_response.lock_lambda_apigw_method_response_200.id,
      aws_api_gateway_integration_response.lock_lambda_apigw_response.id,

      aws_api_gateway_resource.unlock_lambda_apigw.id,
      aws_api_gateway_resource.unlock_path_paramter.id,
      aws_api_gateway_method.unlock_lambda_apigw.id,
      aws_api_gateway_integration.unlock_lambda_apigw.id,
      aws_api_gateway_method_response.unlock_lambda_apigw_method_response_200.id,
      aws_api_gateway_integration_response.unlock_lambda_apigw_response.id,

      aws_api_gateway_resource.run_containers_lambda_apigw.id,
      aws_api_gateway_method.run_containers_lambda_apigw.id,
      aws_api_gateway_integration.run_containers_lambda_apigw.id,
      aws_api_gateway_method_response.run_containers_lambda_apigw_method_response_200.id,
      aws_api_gateway_integration_response.run_containers_lambda_apigw_response.id,

      aws_api_gateway_resource.destroy_containers_lambda_apigw.id,
      aws_api_gateway_method.destroy_containers_lambda_apigw.id,
      aws_api_gateway_integration.destroy_containers_lambda_apigw.id,
      aws_api_gateway_method_response.destroy_containers_lambda_apigw_method_response_200.id,
      aws_api_gateway_integration_response.destroy_containers_lambda_apigw_response.id
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "test_stage" {
  deployment_id = aws_api_gateway_deployment.test.id
  rest_api_id   = aws_api_gateway_rest_api.serverless_lambda_apigw.id
  stage_name    = "test"
}


output "apigw_invoke_url" {
  description = "URL to invoke the API pointing to the stage"
  value       = aws_api_gateway_stage.test_stage.invoke_url
}
