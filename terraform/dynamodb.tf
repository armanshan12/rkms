resource "aws_dynamodb_table" "rkms_keys" {
  provider = "aws.us-east-1"

  name           = "rkms_keys"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
}
