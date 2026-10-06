# AWS Terraform Project

Infrastructure as Code (IaC) project that provisions and deploys a containerized Python application on AWS using Terraform, Docker, Amazon ECR, GitHub Actions and AWS Systems Manager.

The project demonstrates the complete workflow from infrastructure provisioning to automatic application deployment.

## Architecture

```text
GitHub
   |
   | Push to main
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
   | Pull image
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

The subnet is configured with `map_public_ip_on_launch = false`. The EC2 instance receives its public IP through its instance configuration.

### EC2

The application runs on a `t3.micro` EC2 instance.

The instance hosts:

* Docker
* Nginx
* Python application

Traffic follows this path:

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

Nginx works as a reverse proxy, allowing the application to remain listening internally on port 3000 while HTTP traffic enters through port 80.

### Security Group

The security group allows:

* HTTP traffic on port 80
* SSH access from the VPC
* SSH access from explicitly configured IP addresses
* Outbound traffic

The application is exposed through HTTP while the Python service remains behind Nginx.

## Docker and Amazon ECR

The Python application is packaged as a Docker image.

The GitHub Actions workflow:

1. Builds the Docker image.
2. Authenticates with Amazon ECR.
3. Tags the image using the Git commit SHA.
4. Pushes the image to the ECR repository.

Using the commit SHA as the image tag creates a direct relationship between:

```text
Git commit
   |
   v
Docker image
   |
   v
Deployed application
```

This makes it possible to identify exactly which source version is running in the environment.

## CI/CD

The project uses GitHub Actions for automatic deployment.

The workflow is triggered when changes are pushed to the `main` branch.

The pipeline performs the following steps:

```text
Push to GitHub
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
Run health checks
```

The deployment does not require storing long-lived AWS access keys inside GitHub.

Instead, GitHub Actions assumes an AWS IAM role using OpenID Connect.

## AWS IAM

Two main IAM roles are used.

### GitHub Actions role

The GitHub Actions role is responsible for:

* Reading AWS infrastructure information
* Accessing the Terraform remote state
* Pushing Docker images to ECR
* Sending commands through SSM

The role uses GitHub's OIDC provider to authenticate the workflow with AWS.

The current configuration also includes AWS managed `ReadOnlyAccess` permissions. A future improvement is to replace this broad permission with a more restrictive least-privilege policy.

### EC2 role

The EC2 instance uses an IAM role with:

* `AmazonSSMManagedInstanceCore`
* Permission to pull images from the project's ECR repository

This allows the EC2 instance to receive SSM commands and authenticate with ECR without storing AWS credentials on the server.

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

S3 versioning is enabled for the state bucket.

This allows both local Terraform execution and GitHub Actions to work with the same infrastructure state.

State locking is not currently configured and is listed as a future improvement.

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

| File            | Responsibility                           |
| --------------- | ---------------------------------------- |
| `provider.tf`   | AWS provider configuration               |
| `backend.tf`    | Remote Terraform state                   |
| `versions.tf`   | Terraform provider requirements          |
| `variables.tf`  | Configurable project variables           |
| `outputs.tf`    | Useful infrastructure outputs            |
| `networking.tf` | VPC, subnet, routes and Internet Gateway |
| `compute.tf`    | EC2 instance and related resources       |
| `iam.tf`        | IAM roles and permissions                |
| `ecr.tf`        | ECR repository                           |
| `main.tf`       | Project-level configuration              |

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

These values can be retrieved after deployment with:

```bash
terraform output
```

## Application

The application is a simple Python HTTP server.

It listens on:

```text
0.0.0.0:3000
```

The application returns an HTML response confirming that:

* the automatic deployment is working
* the response is generated by Python
* Nginx is operating as a reverse proxy

## Deployment

A successful deployment performs the following operations on the EC2 instance:

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
Verify Nginx -> Python connectivity
```

The container is configured with:

```text
--restart always
```

so Docker automatically attempts to restart it if the container stops.

## Health Check

The deployment includes an application-level health check.

Instead of checking only whether the Docker container is running, the workflow verifies the complete request path:

```text
Nginx :80
   |
   v
Python :3000
```

The workflow executes:

```bash
wget -q -O /dev/null http://localhost && echo NGINX_HEALTH_OK
```

The deployment is considered successful only when the expected health-check result is returned.

## Real Troubleshooting

During development, several real infrastructure and deployment issues were investigated and resolved.

### GitHub Actions OIDC

The first GitHub Actions deployment failed because AWS did not authorize the workflow to assume the IAM role through OIDC.

The IAM trust relationship was reviewed and corrected so the GitHub Actions workflow could assume the AWS role.

After correcting the trust configuration, GitHub Actions successfully authenticated with AWS.

### SSM connectivity

An SSM command initially failed to execute correctly.

The EC2 SSM agent was investigated and restarted, after which SSM communication worked normally.

### Application health check

A direct `curl` test initially produced unexpected output because the application response contained an emoji and the AWS CLI environment had character encoding limitations.

A `curl -I` test returned HTTP 501 because the Python application only implements the GET method.

The test was therefore changed to:

```bash
wget -q -O /dev/null http://localhost
```

This correctly verified the complete Nginx -> Python request path.

### Terraform refactoring

The Terraform configuration was reorganized into multiple files by responsibility.

The infrastructure itself was not recreated because the existing Terraform resource addresses remained unchanged.

After the refactoring:

```text
terraform fmt
terraform validate
terraform plan
terraform apply
```

completed successfully without modifying the existing AWS infrastructure.

## Validation

The project was validated through Terraform, GitHub Actions and the deployed application.

Terraform reported:

```text
Apply complete! Resources: 0 added, 0 changed, 0 destroyed.
```

The deployed application returned:

```text
HTTP 200
```

The response confirmed that Python was running behind Nginx.

The final Terraform refactoring was also successfully processed by GitHub Actions.

## How to Run

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

Apply the infrastructure:

```bash
terraform apply
```

View Terraform outputs:

```bash
terraform output
```

## Security Considerations

The project avoids storing AWS access keys inside the GitHub repository.

GitHub Actions authenticates with AWS through OIDC.

Terraform state is stored remotely in a private S3 bucket with public access blocked.

The EC2 instance uses IAM roles instead of storing AWS credentials locally.

## Future Improvements

Possible future improvements include:

* Implementing Terraform state locking
* Replacing broad `ReadOnlyAccess` permissions with more restrictive IAM policies
* Implementing application rollback
* Adding a dedicated `/health` endpoint
* Creating reusable Terraform modules
* Evaluating an Application Load Balancer instead of direct Nginx exposure
* Adding centralized logging and monitoring
* Separating development and production environments
* Evaluating Kubernetes/EKS for a more advanced deployment architecture

These improvements are intentionally outside the current project scope.

## Project Objective

The objective of this project was to build a practical AWS environment using Infrastructure as Code and demonstrate an end-to-end cloud deployment workflow.

The project combines infrastructure provisioning, IAM, networking, containers, remote Terraform state, CI/CD, AWS Systems Manager and application deployment into a single reproducible workflow.
