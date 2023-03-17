import pytest
import re

from unittest.mock import Mock, patch

from aws_reachability_check.aws.security_groups import SecurityGroups, SecurityGroupIngressRule, SecurityGroupEgressRule


def test_no_ingress_rules():
    src_sgs = SecurityGroups() \
              .add_security_group("sg-12345", "Origination") \
              .add_egress_rule("sg-12345", SecurityGroupEgressRule("sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None))
    dst_sgs = SecurityGroups() \
              .add_security_group("sg-67890", "Destination")
    result = src_sgs.can_connect_to("172.31.0.10/32", dst_sgs, "172.31.128.10/32", 5432)
    assert result.success == None
    assert result.failure == None
    assert result.context == set()


def test_blocked_by_egress_rule_invalid_subnet():
    src_sgs = SecurityGroups() \
              .add_security_group("sg-12345", "Origination") \
              .add_egress_rule("sg-12345", SecurityGroupEgressRule("sgr-12345-01", "tcp", 0, 65535, '172.31.0.0/18', None))
    dst_sgs = SecurityGroups() \
              .add_security_group("sg-67890", "Destination")
    result = src_sgs.can_connect_to("172.31.0.10/32", dst_sgs, "172.31.128.10/32", 5432)
    assert result.success == None
    assert result.failure == "no egress rule allows connections to 172.31.128.10/32 port 5432"
    assert result.context == set()


def test_blocked_by_egress_rule_invalid_port():
    src_sgs = SecurityGroups() \
              .add_security_group("sg-12345", "Origination") \
              .add_egress_rule("sg-12345", SecurityGroupEgressRule("sgr-12345-01", "tcp", 0, 1024, '172.31.0.0/16', None))
    dst_sgs = SecurityGroups() \
              .add_security_group("sg-67890", "Destination")
    result = src_sgs.can_connect_to("172.31.0.10/32", dst_sgs, "172.31.128.10/32", 5432)
    assert result.success == None
    assert result.failure == "no egress rule allows connections to 172.31.128.10/32 port 5432"
    assert result.context == set(["egress rule sgr-12345-01 allows 172.31.128.10/32 but not port 5432"])


def test_ingress_by_sg():
    src_sgs = SecurityGroups() \
              .add_security_group("sg-12345", "Origination") \
              .add_egress_rule("sg-12345", SecurityGroupEgressRule("sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None))
    dst_sgs = SecurityGroups() \
              .add_security_group("sg-67890", "Destination") \
              .add_ingress_rule("sg-67890", SecurityGroupIngressRule("sgr-67890-01", "-1", 5432, 5432, None, "sg-12345"))
    result = src_sgs.can_connect_to("172.31.0.10/32", dst_sgs, "172.31.128.10/32", 5432)
    assert result.success == "sg-67890 has group-based rule sgr-67890-01 that allows sg-12345 on port 5432"
    assert result.failure == None
    assert result.context == set()


def test_ingress_by_sg_incorrect_port():
    src_sgs = SecurityGroups() \
              .add_security_group("sg-12345", "Origination") \
              .add_egress_rule("sg-12345", SecurityGroupEgressRule("sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None))
    dst_sgs = SecurityGroups() \
              .add_security_group("sg-67890", "Destination") \
              .add_ingress_rule("sg-67890", SecurityGroupIngressRule("sgr-67890-01", "-1", 5432, 5432, None, "sg-12345"))
    result = src_sgs.can_connect_to("172.31.0.10/32", dst_sgs, "172.31.128.10/32", 3306)
    assert result.success == None
    assert result.failure == None
    assert result.context == set(["sg-67890 has group-based rule sgr-67890-01 that allows sg-12345 but not on port 3306"])


def test_ingress_by_sg_incorrect_sg():
    src_sgs = SecurityGroups() \
              .add_security_group("sg-12345", "Origination") \
              .add_egress_rule("sg-12345", SecurityGroupEgressRule("sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None))
    dst_sgs = SecurityGroups() \
              .add_security_group("sg-67890", "Destination") \
              .add_ingress_rule("sg-67890", SecurityGroupIngressRule("sgr-67890-01", "-1", 5432, 5432, None, "sg-67890"))
    result = src_sgs.can_connect_to("172.31.0.10/32", dst_sgs, "172.31.128.10/32", 5432)
    assert result.success == None
    assert result.failure == None
    assert result.context == set()


def test_ingress_by_cidr():
    src_sgs = SecurityGroups() \
              .add_security_group("sg-12345", "Origination") \
              .add_egress_rule("sg-12345", SecurityGroupEgressRule("sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None))
    dst_sgs = SecurityGroups() \
              .add_security_group("sg-67890", "Destination") \
              .add_ingress_rule("sg-67890", SecurityGroupIngressRule("sgr-67890-01", "-1", 5432, 5432, "172.31.0.0/16", None))
    result = src_sgs.can_connect_to("172.31.0.10/32", dst_sgs, "172.31.128.10/32", 5432)
    assert result.success == "sg-67890 has cidr-based rule sgr-67890-01 that allows 172.31.0.10/32 on port 5432"
    assert result.failure == None
    assert result.context == set()


def test_ingress_by_cidr_incorrect_port():
    src_sgs = SecurityGroups() \
              .add_security_group("sg-12345", "Origination") \
              .add_egress_rule("sg-12345", SecurityGroupEgressRule("sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None))
    dst_sgs = SecurityGroups() \
              .add_security_group("sg-67890", "Destination") \
              .add_ingress_rule("sg-67890", SecurityGroupIngressRule("sgr-67890-01", "-1", 5432, 5432, "172.31.0.0/16", None))
    result = src_sgs.can_connect_to("172.31.0.10/32", dst_sgs, "172.31.128.10/32", 3306)
    assert result.success == None
    assert result.failure == None
    assert result.context == set(["sg-67890 has cidr-based rule sgr-67890-01 that allows 172.31.0.10/32 but not on port 3306"])
