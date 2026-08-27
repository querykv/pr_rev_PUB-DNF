# Fixture for the Checkov adapter. NOT DEPLOYED — parsed only.
# Deliberately insecure: a public-read bucket with no logging or encryption is
# the shape Checkov's A02 checks exist to catch.
resource "aws_s3_bucket" "public_assets" {
  bucket = "pr-review-fixture-assets"
  acl    = "public-read"
}

resource "aws_security_group" "wide_open" {
  name = "wide-open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
