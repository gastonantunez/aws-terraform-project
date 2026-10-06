output "vpc_id" {
  description = "ID of the main VPC"
  value       = aws_vpc.main.id
}

output "subnet_id" {
  description = "ID of the main subnet"
  value       = aws_subnet.main.id
}

output "ec2_instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.ec2.id
}

output "ec2_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_instance.ec2.public_ip
}

output "ecr_repository_url" {
  description = "URL of the ECR repository"
  value       = aws_ecr_repository.app.repository_url
}