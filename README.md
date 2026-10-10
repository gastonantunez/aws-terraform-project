# AWS Terraform Project

Infrastructure as Code (IaC) project that provisions and deploys a containerized Python application on AWS using Terraform, Docker, Amazon ECR, GitHub Actions and AWS Systems Manager.

The project demonstrates the workflow from infrastructure provisioning to automatic application deployment.

## Architecture

```text
GitHub
   |
   | Push to main or manual trigger
   v
GitHub Actions
   |
   +-- OIDC authentication
   |
   +-- Docker build
   |
   +-- Push image
   v
Amazon ECR
   |
   | Pull image through SSM deployment commands
   v
EC2
   |
   +-- Docker container
   |      |
   |      +-- Python application :3000
   |
   +-- Nginx :80
          |
          v
       Internet
```

Terraform manages the AWS infrastructure, while GitHub Actions handles the application deployment pipeline.

## Technologies

* Terraform
* AWS
* Amazon VPC
* Amazon EC2
* Amazon ECR
* AWS IAM
* AWS Systems Manager (SSM)
* Amazon S3
* Docker
* Nginx
* Python
* Git
* GitHub Actions
* OpenID Connect (OIDC)

## AWS Infrastructure

The project provisions the following infrastructure.

### Networking

* VPC: `10.0.0.0/16`
* Subnet: `10.0.1.0/24`
* Internet Gateway
* Route Table
* Default route to the Internet
* Security Group

The subnet's public IP assignment behavior is configured separately from its route table. Terraform exposes the EC2 instance's public IP through an output.

### EC2

The application runs on an EC2 instance using the Terraform variable `instance_type`, configured with a default value of `t3.micro`.

The instance is associated with:

* The Terraform-managed subnet
* The Terraform-managed Security Group
* An IAM instance profile for AWS service access

The instance runs the containerized Python application as part of the deployment process.

Traffic is intended to follow this path:

```text
Internet
   |
   v
EC2 :80
   |
   v
Nginx
   |
   v
Python application :3000
```

Nginx is intended to work as a reverse proxy, allowing the application to listen on port 3000 while HTTP traffic enters through port 80. The Nginx installation and configuration are not defined in the Terraform files reviewed for this project.

### Security Group

The security group allows:

* HTTP traffic on port 80 from `0.0.0.0/0`
* All outbound traffic

Inbound SSH access on port 22 is not allowed. The GitHub Actions workflow uses AWS Systems Manager (SSM) to send commands to the EC2 instance.

The application is intended to be exposed through HTTP, with Nginx forwarding requests to the Python service on port 3000.

## Docker and Amazon ECR

The Python application is packaged as a Docker image.

The GitHub Actions workflow:

1. Builds the Docker image.
2. Authenticates with Amazon ECR.
3. Tags the image using the Git commit SHA and GitHub Actions run attempt.
4. Pushes the image to the ECR repository.

The image tag follows this format:

```text
<commit-sha>-<run-attempt>
```

This makes it possible to identify the source commit associated with an image and distinguish separate attempts of a workflow run.

## CI/CD

The project uses GitHub Actions for automated application deployment.

The workflow is triggered when changes are pushed to the `main` branch or when manually started through `workflow_dispatch`.

The pipeline performs the following steps:

```text
Push to GitHub or manual trigger
      |
      v
Authenticate with AWS using OIDC
      |
      v
Login to ECR
      |
      v
Build Docker image
      |
      v
Push image to ECR
      |
      v
Terraform init
      |
      v
Terraform validate
      |
      v
Terraform plan
      |
      v
Send commands to EC2 through SSM
      |
      v
Pull new Docker image
      |
      v
Replace running container
      |
      v
Run deployment checks
```

The workflow does not require long-lived AWS access keys to be stored for its AWS authentication flow.

Instead, GitHub Actions assumes an AWS IAM role using OpenID Connect.

The current workflow runs `terraform init`, `terraform validate`, and `terraform plan`. It does not run `terraform apply`. Application deployment is performed through SSM commands.

## AWS IAM

Two main IAM roles are used.

### GitHub Actions role

The GitHub Actions role is responsible for the AWS operations required by the pipeline, including:

* Accessing the Terraform remote state
* Pushing Docker images to ECR
* Sending commands through SSM
* Performing the other AWS operations allowed by its attached IAM policies

The role uses GitHub's OIDC provider to authenticate the workflow with AWS.

The current configuration has previously been documented as including AWS managed `ReadOnlyAccess` permissions. Its present policy attachments should be checked in AWS before treating that detail as a complete description of the role's current permissions.

A future improvement is to restrict permissions according to the principle of least privilege.

### EC2 role

The EC2 instance uses an IAM instance profile.

The project uses this identity for AWS service access, including SSM management and the permissions required to pull container images from ECR.

This allows the EC2 instance to receive SSM commands and access ECR without storing long-lived AWS credentials directly on the server.

## Terraform Remote State

Terraform state is stored remotely in an Amazon S3 bucket.

```text
Terraform
   |
   v
Amazon S3
   |
   v
terraform.tfstate
```

The backend configuration is:

```hcl
terraform {
  backend "s3" {
    bucket = "gaston-aws-terraform-state-183004895136"
    key    = "terraform.tfstate"
    region = "us-east-1"
  }
}
```

This configuration allows Terraform to use the S3 bucket as its remote state backend, provided the bucket exists and the executing identity has the required permissions.

The backend configuration does not define state locking.

Bucket versioning, encryption, and public access settings are managed separately in AWS and are not confirmed by `backend.tf` alone.

## Terraform Structure

The Terraform configuration is organized by responsibility:

```text
.
|-- main.tf
|-- provider.tf
|-- backend.tf
|-- versions.tf
|-- variables.tf
|-- outputs.tf
|-- networking.tf
|-- compute.tf
|-- iam.tf
|-- ecr.tf
|-- app/
|   |-- app.py
|   `-- Dockerfile
|-- .github/
|   `-- workflows/
|       `-- terraform.yml
|-- .gitignore
`-- .terraform.lock.hcl
```

### Main Terraform files

| File | Responsibility |
|---|---|
| `provider.tf` | AWS provider configuration |
| `backend.tf` | Remote Terraform state |
| `versions.tf` | Terraform and provider requirements |
| `variables.tf` | Configurable project variables |
| `outputs.tf` | Useful infrastructure outputs |
| `networking.tf` | VPC, subnet, routes, Internet Gateway and Security Group |
| `compute.tf` | EC2 instance |
| `iam.tf` | IAM roles, instance profile and permissions |
| `ecr.tf` | ECR repository |
| `main.tf` | Project-level configuration comment |

Terraform treats all `.tf` files in the same directory as a single configuration.

The files are separated by responsibility to make the project easier to understand and maintain.

## Variables

The project uses Terraform variables for common configuration values:

```hcl
variable "aws_region" {
  description = "AWS region used by the project"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the main VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for the main subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}
```

This avoids hard-coding these values directly into individual resources.

## Outputs

Terraform exposes useful infrastructure information through outputs:

* VPC ID
* Subnet ID
* EC2 instance ID
* EC2 public IP
* ECR repository URL

These values can be retrieved after initialization and deployment with:

```bash
terraform output
```

The `ec2_public_ip` output reads the public IP address reported by the EC2 resource. The output definition itself does not configure how that address is assigned.

## Application

The application is a simple Python HTTP server built with Python's standard library.

It listens on:

```text
0.0.0.0:3000
```

The application uses `HTTPServer` and `BaseHTTPRequestHandler` and responds to GET requests with an HTML page and HTTP status code `200`.

The HTML response includes messages indicating that:

* The automatic deployment is working
* The response comes from Python
* Nginx is working as a reverse proxy

The Python code displays the Nginx message, but the application code itself does not configure or verify Nginx.

## Deployment

The GitHub Actions workflow performs the following operations on the EC2 instance through SSM:

```text
ECR authentication
      |
      v
Pull new Docker image
      |
      v
Stop previous container
      |
      v
Remove previous container
      |
      v
Start new container
      |
      v
Verify container is running
      |
      v
Check HTTP response through Nginx
```

The container is started with:

```text
--restart always
```

This instructs Docker to attempt to restart the container when it stops, subject to Docker's restart policy behavior.

## Health Check

The deployment includes two basic checks:

1. Verify that `mi-app-container` is running.
2. Check whether an HTTP request to `http://localhost` succeeds and outputs the `NGINX_HEALTH_OK` marker.

The workflow executes:

```bash
wget -q -O /dev/null http://localhost && echo NGINX_HEALTH_OK
```

The workflow then checks for both the container name and the health-check marker in the command output.

This is a basic deployment verification. It does not independently verify the returned HTML content or provide a dedicated application health endpoint.

## Real Troubleshooting

During development, several infrastructure and deployment issues were investigated and resolved.

### GitHub Actions OIDC

The first GitHub Actions deployment failed because AWS did not authorize the workflow to assume the IAM role through OIDC.

The IAM trust relationship was reviewed and corrected so the intended GitHub Actions workflow could assume the AWS role.

After correcting the trust configuration, GitHub Actions successfully authenticated with AWS.

### SSM connectivity

The EC2 SSM agent was investigated and restarted after the instance was not appearing as an online managed node.

SSM communication subsequently worked normally.

### Application health check

A direct `curl` test initially produced unexpected output because the application response contained an emoji and the AWS CLI environment had character-encoding limitations.

A `curl -I` test returned HTTP 501 because the Python application implements GET but does not implement HEAD.

The test was changed to:

```bash
wget -q -O /dev/null http://localhost
```

This checks whether the HTTP request to the local endpoint succeeds. The intended Nginx-to-Python request path depends on the Nginx configuration present on the EC2 instance.

### Terraform refactoring

The Terraform configuration was reorganized into multiple files by responsibility.

The infrastructure was not recreated because the existing Terraform resource addresses remained unchanged.

The refactoring was validated using:

```text
terraform fmt
terraform validate
terraform plan
terraform apply
```

The zero-change `terraform apply` result documented during that refactoring was historical. A later Security Group change removed the SSH ingress rules.

## Validation

The project has been validated through Terraform, GitHub Actions, SSM and the deployed application.

During the Terraform refactoring, the following result was recorded:

```text
Apply complete! Resources: 0 added, 0 changed, 0 destroyed.
```

This result describes that earlier refactoring run, not the subsequent Security Group update.

The GitHub Actions workflow was also run successfully after SSH access was removed. Its deployment checks verify that the application container is running and that the local HTTP check succeeds.

## How to Run

### Prerequisites

Before running the commands below, ensure that:

* Git is installed.
* Terraform is installed.
* AWS CLI is installed and configured with appropriate credentials.
* The configured S3 backend bucket already exists and is accessible.
* The AWS resources and permissions required by the Terraform configuration are available.
* The GitHub Actions IAM role, OIDC provider, ECR repository and SSM configuration are prepared if you intend to run the CI/CD pipeline.

Clone the repository:

```bash
git clone https://github.com/gastonantunez/aws-terraform-project.git
cd aws-terraform-project
```

Initialize Terraform:

```bash
terraform init
```

Validate the configuration:

```bash
terraform validate
```

Review the planned changes:

```bash
terraform plan
```

Apply infrastructure changes only after reviewing the plan:

```bash
terraform apply
```

View Terraform outputs:

```bash
terraform output
```

These commands describe the general Terraform workflow. They do not guarantee that a fresh deployment can be created from an empty AWS account without first preparing the backend, permissions and required resources.

## Security Considerations

The project uses GitHub Actions OIDC to authenticate with AWS rather than relying on long-lived AWS access keys in the workflow.

The EC2 Security Group does not permit inbound SSH access.

SSM is used for remote command execution, and the EC2 instance uses an IAM instance profile for AWS service access.

The S3 backend should be protected by appropriate bucket policies, IAM permissions, encryption and public access settings. These bucket properties should be verified directly in AWS.

IAM policies should be reviewed periodically and restricted to the minimum permissions required by each role.

## Future Improvements

Possible future improvements include:

* Implementing and configuring Terraform state locking
* Replacing broad IAM permissions with more restrictive least-privilege policies
* Implementing application rollback
* Adding a dedicated `/health` endpoint
* Creating reusable Terraform modules
* Evaluating an Application Load Balancer instead of direct Nginx exposure
* Adding centralized logging and monitoring
* Separating development and production environments
* Evaluating Kubernetes/EKS for a more advanced deployment architecture

These improvements are intentionally outside the current project scope.

## Project Objective

The objective of this project is to build a practical AWS environment using Infrastructure as Code and demonstrate a cloud application deployment workflow.

The project combines infrastructure provisioning, IAM, networking, containers, remote Terraform state, CI/CD, AWS Systems Manager and application deployment into a single project.
