provider "aws" {
  region = var.aws_region
}

resource "aws_vpc" "main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name      = "VPC-${var.stack_name}"
    Terraform = "true"
  }
}



resource "aws_vpc_dhcp_options" "main_dhcp_options" {
  domain_name_servers = ["AmazonProvidedDNS"]
  domain_name         = "example.com"
}

# Associate DHCP option set with VPC
resource "aws_vpc_dhcp_options_association" "main_dhcp_association" {
  vpc_id          = aws_vpc.main_vpc.id
  dhcp_options_id = aws_vpc_dhcp_options.main_dhcp_options.id
}


resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.main_vpc.id
  tags = {
    Name      = "Internet-Gateway-${var.stack_name}"
    Terraform = "true"
  }
}


resource "aws_eip" "nat_eip" {
  vpc        = true
  depends_on = [aws_internet_gateway.internet_gateway]
  tags = {
    Name      = "EIP-${var.stack_name}"
    Terraform = "true"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public.id
  depends_on    = [aws_internet_gateway.internet_gateway]
  tags = {
    Name      = "Nat-Gateway-${var.stack_name}"
    Terraform = "true"
  }
}





resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.main_vpc.id
  cidr_block = "10.0.1.0/24"

  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true

  tags = {
    Name      = "public-${var.stack_name}"
    Terraform = "true"
  }
}


resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main_vpc.id
  cidr_block = "10.0.2.0/24"

  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = false

  tags = {
    Name      = "private-${var.stack_name}"
    Terraform = "true"
  }
}


resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main_vpc.id
  tags = {
    Name      = "public-route-table-${var.stack_name}"
    Terraform = "true"
  }
}


resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main_vpc.id
  tags = {
    Name      = "private-route-table-${var.stack_name}"
    Terraform = "true"
  }
}



resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.internet_gateway.id
}



resource "aws_route" "private_nat_gateway" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}



resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}


resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}


resource "aws_vpc_endpoint" "s3_endpoint" {
  vpc_id       = aws_vpc.main_vpc.id
  service_name = "com.amazonaws.${data.aws_region.current.name}.s3"
  policy       = <<POLICY
{
  "Statement": [
    {
      "Action": "*",
      "Effect": "Allow",
      "Resource": "*",
      "Principal": "*"
    }
  ]
}
POLICY
}

resource "aws_vpc_endpoint_route_table_association" "s3_endpoint_association" {
  route_table_id  = aws_route_table.private.id
  vpc_endpoint_id = aws_vpc_endpoint.s3_endpoint.id
}


data "aws_region" "current" {}


# Create a security group for the CodeBuild project
resource "aws_security_group" "codebuild_sg" {
  name        = "codebuild_sg"
  description = "Security group for CodeBuild"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow access from the VPC CIDR range
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name      = "sg-${var.stack_name}"
    Terraform = "true"
  }
}


# Create a security group for the CodeBuild project
resource "aws_security_group" "ecs_sg" {
  name        = "ecs_sg"
  description = "Security group for ECS"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name      = "sg-${var.stack_name}"
    Terraform = "true"
  }
}




resource "aws_codebuild_project" "codebuild_project" {
  name         = "codebuild-${var.stack_name}"
  description  = "CodeBuild project for building Docker image and pushing to ECR"
  service_role = aws_iam_role.codebuild_role.arn
  vpc_config {
    vpc_id             = aws_vpc.main_vpc.id
    subnets            = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.codebuild_sg.id]
  }
  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/standard:5.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = true
  }
  source {
    type            = "CODEPIPELINE"
    buildspec       = "buildspec.yml"
    git_clone_depth = 1
  }

  artifacts {
    type = "CODEPIPELINE"
  }

  logs_config {
    cloudwatch_logs {
      status      = "ENABLED"
      group_name  = "/aws/codebuild/codebuild-spring-boot"
      stream_name = "{codebuild-spring-boot}-{build-id}"

    }
  }

}


# Create the CodeBuild IAM service role
resource "aws_iam_role" "codebuild_role" {
  name               = "codebuild_role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}



resource "aws_iam_policy" "codebuild_vpc_policy" {
  name        = "codebuild-vpc-policy"
  description = "Allows CodeBuild to access resources in a VPC"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:AssignPrivateIpAddresses",
          "ec2:UnassignPrivateIpAddresses",
          "ec2:CreateNetworkInterface",
          "ec2:DescribeDhcpOptions",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:CreateNetworkInterfacePermission"
        ]
        Effect   = "Allow"
        Resource = "*"
        }, {
        "Action" : [
          "logs:GetLogEvents",
          "logs:CreateLogGroup",
          "logs:GetLogEvents",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ],
        "Effect" : "Allow",
        "Resource" : "*"
        }, {
        "Action" : [
          "s3:Get*",
          "s3:List*"
        ],
        "Effect" : "Allow",
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "codebuild_vpc_policy_attachment" {
  policy_arn = aws_iam_policy.codebuild_vpc_policy.arn
  role       = aws_iam_role.codebuild_role.name
}


resource "aws_iam_role_policy_attachment" "codebuild_vpc_2_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonVPCFullAccess"
  role       = aws_iam_role.codebuild_role.name
}

resource "aws_iam_role_policy_attachment" "codebuild_admin_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  role       = aws_iam_role.codebuild_role.name
}


# Attach the necessary policies to the CodeBuild IAM role
resource "aws_iam_role_policy_attachment" "codebuild_policy_attachment" {
  role       = aws_iam_role.codebuild_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeBuildAdminAccess"
}

data "aws_ecr_repository" "existing_ecr_repository" {
  name = "spring_boot_ecr"
}


resource "aws_ecr_repository_policy" "ecr_repository_policy" {
  repository = data.aws_ecr_repository.existing_ecr_repository.name
  policy     = <<EOF
{
  "Version": "2008-10-17",
  "Statement": [
    {
      "Sid": "AllowPushPull",
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.codebuild_role.arn}"
      },
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:PutImage",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload"
      ]
    }
  ]
}
EOF
}


resource "aws_ecs_cluster" "ecs_cluster" {
  name = "my_ecs-${var.stack_name}"
}

resource "aws_ecs_task_definition" "ecs_task_definition" {
  family                   = "my_ecs_task"
  container_definitions    = <<EOF
[
  {
    "name": "spring_boot_ecr",
    "image": "006343592531.dkr.ecr.us-west-2.amazonaws.com/spring_boot_ecr:latest",
    "portMappings": [
      {
        "containerPort": 8080,
        "protocol": "tcp"
      }
    ]
   
  }
]
EOF
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  memory                   = 512
  cpu                      = 256
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
}

data "aws_iam_policy_document" "ecs_task_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_task_execution_role" {
  name               = "ecs-task-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json
}


data "aws_iam_policy" "ecs_task_execution_role" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = data.aws_iam_policy.ecs_task_execution_role.arn
}

# Create the ECS Fargate service
resource "aws_ecs_service" "ecs_service" {
  name            = "my_ecs_service"
  cluster         = aws_ecs_cluster.ecs_cluster.id
  task_definition = aws_ecs_task_definition.ecs_task_definition.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = [aws_subnet.public.id]
    security_groups  = [aws_security_group.ecs_sg.id]
    assign_public_ip = true
  }
}


# Create the CodeStar Connection for GitHub
resource "aws_codestarconnections_connection" "github_connection" {
  provider_type  = "GitHub"
  name = "Github-${var.stack_name}"
 
}


resource "aws_codepipeline" "pipeline" {
  name = "codebuild-${var.stack_name}"


  role_arn = aws_iam_role.codepipeline_role.arn

  artifact_store {
    location = module.s3_bucket.s3_bucket_id
    type     = "S3"
  }


  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["source"]

      configuration = {
        ConnectionArn    = aws_codestarconnections_connection.github_connection.arn
        FullRepositoryId = "kmng/springrest"
        BranchName       = "main"
      }
    }
  }

  stage {
    name = "Build"

    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["source"]
      output_artifacts = ["imagedefinitions"]
      version          = "1"

      configuration = {
        ProjectName = aws_codebuild_project.codebuild_project.name
      }
    }
  }


  stage {
    name = "Deploy"

    action {
      name     = "Deploy"
      category = "Deploy"
      owner    = "AWS"
      provider = "ECS"
      version  = "1"
      input_artifacts = ["imagedefinitions"]

      configuration = {
        ClusterName = aws_ecs_cluster.ecs_cluster.id
        ServiceName = aws_ecs_service.ecs_service.name
        FileName    = "imagedefinitions.json"
      }
    }
  }


}

# resource "aws_codepipeline" "pipeline" {
#   name = "codebuild-${var.stack_name}"


#   role_arn = aws_iam_role.codepipeline_role.arn

#   artifact_store {
#     location = module.s3_bucket.s3_bucket_id
#     type     = "S3"
#   }


#   stage {
#     name = "Source"

#     action {
#       name             = "Source"
#       category         = "Source"
#       owner            = "ThirdParty"
#       provider         = "GitHub"
#       version          = "1"
#       output_artifacts = ["source"]

#       configuration = {
#         Owner      = "kmng"
#         Repo       = "springrest"
#         Branch     = "main"
#         OAuthToken = var.github_access_token
#       }
#     }
#   }

#   stage {
#     name = "Build"

#     action {
#       name             = "Build"
#       category         = "Build"
#       owner            = "AWS"
#       provider         = "CodeBuild"
#       input_artifacts  = ["source"]
#       output_artifacts = ["imagedefinitions"]
#       version          = "1"

#       configuration = {
#         ProjectName = aws_codebuild_project.codebuild_project.name
#       }
#     }
#   }


#   stage {
#     name = "Deploy"

#     action {
#       name     = "Deploy"
#       category = "Deploy"
#       owner    = "AWS"
#       provider = "ECS"
#       version  = "1"
#       input_artifacts = ["imagedefinitions"]

#       configuration = {
#         ClusterName = aws_ecs_cluster.ecs_cluster.id
#         ServiceName = aws_ecs_service.ecs_service.name
#         FileName    = "imagedefinitions.json"
#       }
#     }
#   }


# }

# Create the CodePipeline IAM service role
resource "aws_iam_role" "codepipeline_role" {
  name               = "codepipeline_role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codepipeline.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# Attach the necessary policies to the CodePipeline IAM role
resource "aws_iam_role_policy_attachment" "codepipeline_policy_attachment" {
  role       = aws_iam_role.codepipeline_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSCodePipeline_FullAccess"
}



resource "aws_iam_role_policy" "codepipelinerole_policy" {
  name = "CodepipelineRole-Policy"
  role = aws_iam_role.codepipeline_role.name

  policy = <<EOF
{
    "Statement": [
        {
            "Action": [
                "codestar-connections:*"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:GetBucketVersioning"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"

            ],
            "Resource": [
                "arn:aws:s3:::*",
                "arn:aws:s3:::*/*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "codecommit:CancelUploadArchive",
                "codecommit:GetBranch",
                "codecommit:GetCommit",
                "codecommit:GetUploadArchiveStatus",
                "codecommit:UploadArchive"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "codedeploy:CreateDeployment",
                "codedeploy:GetApplicationRevision",
                "codedeploy:GetDeployment",
                "codedeploy:GetDeploymentConfig",
                "codedeploy:RegisterApplicationRevision"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "elasticbeanstalk:*",
                "ec2:*",
                "elasticloadbalancing:*",
                "autoscaling:*",
                "cloudwatch:*",
                "s3:*",
                "sns:*",
                "cloudformation:*",
                "rds:*",
                "sqs:*",
                "ecs:*",
                "iam:PassRole"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "lambda:*"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "opsworks:CreateDeployment",
                "opsworks:DescribeApps",
                "opsworks:DescribeCommands",
                "opsworks:DescribeDeployments",
                "opsworks:DescribeInstances",
                "opsworks:DescribeStacks",
                "opsworks:UpdateApp",
                "opsworks:UpdateStack"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "cloudformation:CreateStack",
                "cloudformation:DeleteStack",
                "cloudformation:DescribeStacks",
                "cloudformation:UpdateStack",
                "cloudformation:CreateChangeSet",
                "cloudformation:DeleteChangeSet",
                "cloudformation:DescribeChangeSet",
                "cloudformation:ExecuteChangeSet",
                "cloudformation:SetStackPolicy",
                "cloudformation:ValidateTemplate",
                "iam:PassRole"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "codebuild:BatchGetBuilds",
                "codebuild:StartBuild"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Effect": "Allow",
            "Resource": "*"
        },
        {
            "Action": [
                "codestar-connections:UseConnection"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }

    ],
    "Version": "2012-10-17"
}
EOF
}

module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"

  bucket = "s3-bucket-${var.stack_name}-${formatdate("YYYYMMDDhhmmss", timestamp())}"
  versioning = {
    enabled = true
  }
  force_destroy = true

  # Add any other S3 bucket configuration options here
}
