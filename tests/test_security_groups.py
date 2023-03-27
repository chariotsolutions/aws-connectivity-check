# Copyright 2023, Chariot Solutions
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import pytest
import re

from unittest.mock import Mock, patch

from connectivity_check.aws.security_groups import SecurityGroupRules


def test_no_ingress_rules():
    src_rules = SecurityGroupRules() \
                .add_egress_rule("sg-12345", "Origination", "sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None)
    dst_rules = SecurityGroupRules()
    result = src_rules.can_connect_to("172.31.0.10/32", "172.31.128.10/32", 5432, dst_rules)
    assert result.success == None
    assert result.failure == None
    assert result.context == set()


def test_blocked_by_egress_rule_invalid_subnet():
    src_rules = SecurityGroupRules() \
                .add_egress_rule("sg-12345", "Origination", "sgr-12345-01", "tcp", 0, 65535, '172.31.0.0/18', None)
    dst_rules = SecurityGroupRules()
    result = src_rules.can_connect_to("172.31.0.10/32", "172.31.128.10/32", 5432, dst_rules)
    assert result.success == None
    assert result.failure == "no egress rule allows connections to 172.31.128.10/32 port 5432"
    assert result.context == set()


def test_blocked_by_egress_rule_invalid_port():
    src_rules = SecurityGroupRules() \
                .add_egress_rule("sg-12345", "Origination", "sgr-12345-01", "tcp", 0, 1024, '0.0.0.0/0', None)
    dst_rules = SecurityGroupRules()
    result = src_rules.can_connect_to("172.31.0.10/32", "172.31.128.10/32", 5432, dst_rules)
    assert result.success == None
    assert result.failure == "no egress rule allows connections to 172.31.128.10/32 port 5432"
    assert result.context == set(["egress rule sgr-12345-01 allows 172.31.128.10/32 but not port 5432"])


def test_ingress_by_sg():
    src_rules = SecurityGroupRules() \
                .add_egress_rule("sg-12345", "Origination", "sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None)
    dst_rules = SecurityGroupRules() \
                .add_ingress_rule("sg-67890", "Destination", "sgr-67890-01", "-1", 5432, 5432, "sg-12345", None, None)
    result = src_rules.can_connect_to("172.31.0.10/32", "172.31.128.10/32", 5432, dst_rules)
    assert result.success == "sg-67890 has group-based rule sgr-67890-01 that allows sg-12345 on port 5432"
    assert result.failure == None
    assert result.context == set()


def test_ingress_by_sg_incorrect_port():
    src_rules = SecurityGroupRules() \
                .add_egress_rule("sg-12345", "Origination", "sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None)
    dst_rules = SecurityGroupRules() \
                .add_ingress_rule("sg-67890", "Destination", "sgr-67890-01", "-1", 5432, 5432, "sg-12345", None, None)
    result = src_rules.can_connect_to("172.31.0.10/32", "172.31.128.10/32", 3306, dst_rules)
    assert result.success == None
    assert result.failure == None
    assert result.context == set(["sg-67890 has group-based rule sgr-67890-01 that allows sg-12345 but not on port 3306"])


def test_ingress_by_sg_incorrect_sg():
    src_rules = SecurityGroupRules() \
                .add_egress_rule("sg-12345", "Origination", "sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None)
    dst_rules = SecurityGroupRules() \
                .add_ingress_rule("sg-67890", "Destination", "sgr-67890-01", "-1", 5432, 5432, "sg-67890", None, None)
    result = src_rules.can_connect_to("172.31.0.10/32", "172.31.128.10/32", 5432, dst_rules)
    assert result.success == None
    assert result.failure == None
    assert result.context == set()


def test_ingress_by_cidr():
    src_rules = SecurityGroupRules() \
                .add_egress_rule("sg-12345", "Origination", "sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None)
    dst_rules = SecurityGroupRules() \
                .add_ingress_rule("sg-67890", "Destination", "sgr-67890-01", "-1", 5432, 5432, None, "172.31.0.0/16", None)
    result = src_rules.can_connect_to("172.31.0.10/32", "172.31.128.10/32", 5432, dst_rules)
    assert result.success == "sg-67890 has cidr-based rule sgr-67890-01 that allows 172.31.0.10/32 on port 5432"
    assert result.failure == None
    assert result.context == set()


def test_ingress_by_cidr_incorrect_port():
    src_rules = SecurityGroupRules() \
                .add_egress_rule("sg-12345", "Origination", "sgr-12345-01", "tcp", 0, 65535, '0.0.0.0/0', None)
    dst_rules = SecurityGroupRules() \
                .add_ingress_rule("sg-67890", "Destination", "sgr-67890-01", "-1", 5432, 5432, None, "172.31.0.0/16", None)
    result = src_rules.can_connect_to("172.31.0.10/32", "172.31.128.10/32", 3306, dst_rules)
    assert result.success == None
    assert result.failure == None
    assert result.context == set(["sg-67890 has cidr-based rule sgr-67890-01 that allows 172.31.0.10/32 but not on port 3306"])
