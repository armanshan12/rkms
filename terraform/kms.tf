
# *** us-east-1 ***

resource "aws_kms_key" "us_east_1" {
  provider = "aws.us-east-1"

  description             = "RKMS master key in us-east-1"
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "us_east_1" {
  provider = "aws.us-east-1"

  name          = "alias/rkms-us-east-1"
  target_key_id = "${aws_kms_key.us_east_1.key_id}"
}


# *** us-east-2 ***

resource "aws_kms_key" "us_east_2" {
  provider = "aws.us-east-2"

  description             = "RKMS master key in us-east-2"
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "us_east_2" {
  provider = "aws.us-east-2"
  
  name          = "alias/rkms-us-east-2"
  target_key_id = "${aws_kms_key.us_east_2.key_id}"
}


# *** us-west-1 ***

resource "aws_kms_key" "us_west_1" {
  provider = "aws.us-west-1"

  description             = "RKMS master key in us-west-1"
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "us_west_1" {
  provider = "aws.us-west-1"

  name          = "alias/rkms-us-west-1"
  target_key_id = "${aws_kms_key.us_west_1.key_id}"
}
