#################################################################
# Terraform template that will deploy two VMs in AWS with LAMP
#
# Version: 1.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Licensed Materials - Property of IBM
#
# ©Copyright IBM Corp. 2017, 2018.
#
##################################################################

#########################################################
# Define the AWS provider
#########################################################
provider "aws" {
  version = "~> 2.0"
  region  = "${var.aws_region}"
}

#########################################################
# Helper module for tagging
#########################################################
module "camtags" {
  source = "../Modules/camtags"
}

#########################################################
# Define the variables
#########################################################
variable "aws_region" {
  description = "AWS region to launch servers"
  default     = "ap-south-1"
}

#Variable : AWS image name
#variable "aws_image" {
#  type = "string"
#  description = "Operating system image id / template that should be used when creating the virtual image"
#  default = "ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"
#}

#variable "aws_ami_owner_id" {
#  description = "AWS AMI Owner ID"
#  default = "099720109477"
#}

# Lookup for AMI based on image name and owner ID
#data "aws_ami" "aws_ami" {
#  most_recent = true
#  filter {
#    name = "name"
#    values = ["${var.aws_image}*"]
#  }
#  owners = ["${var.aws_ami_owner_id}"]
#}

#variable "php_instance_name" {
#  description = "The hostname of server with php"
#  default     = "lampPhp"
#}

#variable "db_instance_name" {
#  description = "The hostname of server with mysql"
#  default     = "lampDb"
#}

#variable "network_name_prefix" {
#  description = "The prefix of names for VPC, Gateway, Subnet and Security Group"
#  default     = "opencontent-lamp"

#}

#variable "public_key_name" {
#  description = "Name of the public SSH key used to connect to the servers"
#  default     = "cam-public-key-lamp"
#}

#variable "public_key" {
#  description = "Public SSH key used to connect to the servers"
#}


#variable "aws_vpc_id" {
#    default = "Terraform_PaloAlto"
#}

#variable "aws_vpc_id" {}

variable "VPC_CIDR" {
    default = "10.0.0.0/16"
}
variable "VPC_SUBNET_PUBLIC" {
    default = "10.0.0.0/24" 
}

variable "VPC_SUBNET_PRIVATE" {
    default = "10.0.134.0/24"
}

#variable "aws_security_group_id" {}
#variable "aws_subnet_public_id" {}
#variable "aws_subnet_private_id" {}
#variable "aws_internet_gateway_id" {}

variable "AWS_REGION" {
    default = "ap-south-1"
}
#variable "PATH_TO_PRIVATE_KEY" {}
#variable "PATH_TO_PUBLIC_KEY" {}

variable "OWNER" {
    default = "CISO"
}
variable "ENVIRONMENT" {
    default = "cam_aws"
}
variable "PROJECT" {
    default = "Palo Alto POC"
}

variable "FW_MGMT_PUBLIC" {
    default = "10.0.0.10"
}
variable "FW_GWY_PUBLIC" {
    default = "10.0.0.20"
}
variable "FW_GWY_PRIVATE" {
    default = "10.0.134.10"
}
variable "REDHAT_PRIVATE" {
    default = "10.0.134.25"
}

variable "FW_STATIC_IP" {
    default = "13.57.175.0"
}


variable "FW_NAME" {
    default = "aws-paloalto-ap-south-1"
}

  
  
#variable "cam_user" {
#  description = "User to be added into db and sshed into servers"
#  default     = "camuser"
#}

#variable "cam_pwd" {
#  description = "Password for cam user (minimal length is 8)"
#}


#########################################################
# Build network
#########################################################

# Creating VPC
resource "aws_vpc" "cam_aws" {
    cidr_block = "${var.VPC_CIDR}"
    instance_tenancy = "default"
    enable_dns_support = "true"
    enable_dns_hostnames = "true"
    enable_classiclink = "false"

    tags {
        Name = "Palo Alto Test VPC"
        Owner = "${var.OWNER}"
        Environment = "${var.ENVIRONMENT}"
        Project = "${var.PROJECT}"
    }
}

#Create a subnet in the VPC to be the Security Gateway Subnet.
resource "aws_subnet" "cam_aws_subnet_public" {
    vpc_id = "${aws_vpc.cam_aws.id}"
    cidr_block = "${var.VPC_SUBNET_PUBLIC}"
    map_public_ip_on_launch = "true"
    availability_zone = "ap-south-1a"

    tags {
        Name = "test-subnet-public"
        Owner = "${var.OWNER}"
        Environment = "${var.ENVIRONMENT}"
        Project = "${var.PROJECT}"
    }
}
  
  # Internal subnet
resource "aws_subnet" "cam_aws_subnet_private" {
    vpc_id = "${aws_vpc.cam_aws.id}"
    cidr_block = "${var.VPC_SUBNET_PRIVATE}"
    map_public_ip_on_launch = "true"
    availability_zone = "ap-south-1a"

    tags {
        Name = "cam_aws-subnet-private"
        Owner = "${var.OWNER}"
        Environment = "${var.ENVIRONMENT}"
        Project = "${var.PROJECT}"
    }
}
  

# Creating the Amazon VPC Internet Gateway Attached to VPC
resource "aws_internet_gateway" "cam_aws_gwy" {
    vpc_id = "${aws_vpc.cam_aws.id}"

    tags {
        Name = "cam_aws-gwy"
        Owner = "${var.OWNER}"
        Environment = "${var.ENVIRONMENT}"
        Project = "${var.PROJECT}"
    }
}  
  
  resource "aws_internet_gateway" "cam_aws_gwy_private" {
    vpc_id = "${aws_vpc.cam_aws.id}"

    tags {
        Name = "cam_aws-gwy_private"
        Owner = "${var.OWNER}"
        Environment = "${var.ENVIRONMENT}"
        Project = "${var.PROJECT}"
    }
}  

  resource "aws_route_table" "acme_route_public" {
    vpc_id = "${aws_vpc.cam_aws.id}"
    route {
      cidr_block = "0.0.0.0/0"
      gateway_id = "${aws_internet_gateway.cam_aws_gwy.id}"
    }
    tags {
      Name = "acme-route-public"
      Owner = "${var.OWNER}"
      Environment = "${var.ENVIRONMENT}"
      Project = "${var.PROJECT}"
    }
}
  
  # route associations public
resource "aws_route_table_association" "acme_assc_public" {
  subnet_id = "${aws_subnet.cam_aws_subnet_public.id}"
  route_table_id = "${aws_route_table.acme_route_public.id}"
}
  
  resource "aws_route_table" "acme_route_private" {
    vpc_id = "${aws_vpc.cam_aws.id}"
    route {
      cidr_block = "0.0.0.0/0"
      gateway_id = "${aws_internet_gateway.cam_aws_gwy_private.id}"
    }
    tags {
      Name = "acme-route-private"
      Owner = "${var.OWNER}"
      Environment = "${var.ENVIRONMENT}"
      Project = "${var.PROJECT}"
    }
}
  # route associations private
resource "aws_route_table_association" "acme_assc_private" {
  subnet_id = "${aws_subnet.cam_aws_subnet_private.id}"
  route_table_id = "${aws_route_table.acme_route_private.id}"
}

  # Creating Security Groups
resource "aws_security_group" "cam_aws_sg" {
  vpc_id = "${aws_vpc.cam_aws.id}"
  name = "cam_aws-sg"
  description = "Security group that allows ssh and all egress traffic"
  egress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
  }

  tags {
    Name = "cam_aws-sg"
    Owner = "${var.OWNER}"
    Environment = "${var.ENVIRONMENT}"
    Project = "${var.PROJECT}"
  }
}

  #Creating Key Pair 
resource "aws_key_pair" "cam_aws_deployment" {
  key_name = "cam_aws"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCNovnxtCRrEL048khf2ZTXkn52RZ5Mt817wUhAbAMDcwhb8W4H8OomvqoCzNdsLxzk8WbmbHifrIF1UboEtgfajq0ZhHKz7VfYDG56Dp8iPq/1iVq6iTiZUoauEujeAAV5gYIZR+pQ9yPiHV98AEPomIq4hwM7MWOWLHjSnJvVx2Nl7iJ944rm5rdMUY1fiyQGJP+034l4+FoBRDeJDTMIaT1FnGkFXkpmavqtfXczKI51SKQaGqmq4vaVQUmTO6KRbpgr2iWW5GjL+T14ux2TPcb/dCj0zAxHwJ5xzcIPSMpiXdNn4UkRW1wBBEWdBHID4UhuGJFj6aOml+hHWkp pradeepkumarm"
}
  
  resource "tls_private_key" "ssh" {
  algorithm = "RSA"
}

resource "aws_key_pair" "temp_public_key" {
  key_name   = "cam_aws-temp"
  public_key = "${tls_private_key.ssh.public_key_openssh}"
}
  
resource "aws_network_interface" "acme_FWPublicNetworkInterface" {
  subnet_id       = "${aws_subnet.cam_aws_subnet_public.id}"
  security_groups = ["${aws_security_group.cam_aws_sg.id}"]
  source_dest_check = false
  private_ips_count = 1
  private_ips = ["${var.FW_MGMT_PUBLIC}"]
  tags {
    Name = "acme-pafw-instance-mgmt-public-intf"
    Owner = "${var.OWNER}"
    Environment = "${var.ENVIRONMENT}"
    Project = "${var.PROJECT}"
  }
}
resource "aws_network_interface" "acme_pafw_instance_public" {
  subnet_id = "${aws_subnet.cam_aws_subnet_public.id}"
  private_ips = ["${var.FW_GWY_PUBLIC}"]
  source_dest_check = "false"
  security_groups = ["${aws_security_group.cam_aws_sg.id}"]
  tags {
    Name = "acme-pafw-instance-public-intf"
    Owner = "${var.OWNER}"
    Environment = "${var.ENVIRONMENT}"
    Project = "${var.PROJECT}"
  }
}
resource "aws_network_interface" "acme_pafw_instance_private" {
  subnet_id = "${aws_subnet.cam_aws_subnet_private.id}"
  private_ips = ["${var.FW_GWY_PRIVATE}"]
  source_dest_check = "false"
  security_groups = ["${aws_security_group.cam_aws_sg.id}"]
  tags {
    Name = "acme-pafw-instance-private-intf"
    Owner = "${var.OWNER}"
    Environment = "${var.ENVIRONMENT}"
    Project = "${var.PROJECT}"
  }
}
  
resource "aws_instance" "RHEL" {
  instance_type               = "t2.micro"
  ami                         = "ami-003b12a9a1ee83922"
  subnet_id                   = "${aws_subnet.cam_aws_subnet_private.id}"
  vpc_security_group_ids      = ["${aws_security_group.cam_aws_sg.id}"]
  key_name = "cam_aws-temp"
  associate_public_ip_address = true

 tags {
    Name = "RHEL-instance"
    Owner = "${var.OWNER}"
    Environment = "${var.ENVIRONMENT}"
    Project = "${var.PROJECT}"
  }
  
  connection {
    user        = "ec2-user"
    private_key = "${tls_private_key.ssh.private_key_pem}"
    host        = "${self.public_ip}"
    bastion_host        = "${var.bastion_host}"
    bastion_user        = "${var.bastion_user}"
    bastion_private_key = "${ length(var.bastion_private_key) > 0 ? base64decode(var.bastion_private_key) : var.bastion_private_key}"
    bastion_port        = "${var.bastion_port}"
    bastion_host_key    = "${var.bastion_host_key}"
    bastion_password    = "${var.bastion_password}"        
  }
 provisioner "remote-exec" {
    inline = [
      "echo yes | sudo yum install zip ; echo yes | sudo yum install unzip ; sudo curl -L -O https://ibm.box.com/shared/static/odevtrqvhdmwaz6gypb2jkd856yldt4i.zip; sudo unzip ./*.zip; sudo bash tf.sh"
    ]
  }}
  
resource "aws_instance" "kali" {
  instance_type               = "t2.micro"
  ami                         = "ami-06fea6d88c62d4e26"
  subnet_id                   = "${aws_subnet.cam_aws_subnet_public.id}"
  vpc_security_group_ids      = ["${aws_security_group.cam_aws_sg.id}"]
  key_name = "cam_aws-temp"
  associate_public_ip_address = true

 tags {
    Name = "kali-instance"
    Owner = "${var.OWNER}"
    Environment = "${var.ENVIRONMENT}"
    Project = "${var.PROJECT}"
  }
  
  connection {
    user        = "ec2-user"
    private_key = "${tls_private_key.ssh.private_key_pem}"
    host        = "${self.public_ip}"
    bastion_host        = "${var.bastion_host}"
    bastion_user        = "${var.bastion_user}"
    bastion_private_key = "${ length(var.bastion_private_key) > 0 ? base64decode(var.bastion_private_key) : var.bastion_private_key}"
    bastion_port        = "${var.bastion_port}"
    bastion_host_key    = "${var.bastion_host_key}"
    bastion_password    = "${var.bastion_password}"        
  }
 provisioner "remote-exec" {
    inline = [
      "sudo curl -L -O https://ibm.box.com/shared/static/6oc31mh87tywrwwi5yc9fodor891q5py.zip; sudo unzip ./*.zip; sudo bash tf.sh"
    ]
  }}
  
  
