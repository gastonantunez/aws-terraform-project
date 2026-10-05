terraform {
  backend "s3" {
    bucket = "gaston-aws-terraform-state-183004895136"
    key    = "terraform.tfstate"
    region = "us-east-1"
  }
}