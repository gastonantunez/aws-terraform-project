resource "aws_instance" "ec2" {
  ami           = "ami-0fef201115eefe936"
  instance_type = "t3.micro"

  subnet_id = aws_subnet.main.id

  vpc_security_group_ids = [
    aws_security_group.ec2.id
  ]

  iam_instance_profile = aws_iam_instance_profile.ec2.name

  tags = {
    Name = "terraform-ec2"
  }
}