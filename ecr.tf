resource "aws_ecr_repository" "app" {
  name                 = "mi-app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "terraform-ecr-mi-app"
  }
}