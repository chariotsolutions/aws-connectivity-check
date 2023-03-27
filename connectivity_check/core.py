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


""" Defines core data classes for the reachability analyzer.
    """

from collections import namedtuple

FromInfo = namedtuple('FromInfo', ['resource_type', 'resource_name', 'vpc', 'subnet_ids', 'security_group_ids', 'cidr'])

ToInfo = namedtuple('ToInfo', ['resource_type', 'resource_name', 'vpc', 'subnet_ids', 'security_group_ids', 'cidr', 'port'])

Subnet = namedtuple('Subnet', ['vpc_id', 'subnet_id', 'cidr', 'availability_zone', 'route_table', 'access_to_internet'])

RouteTable = namedtuple('RouteTable', ['vpc_id', 'route_table_id', 'gateway'])

SecurityGroupIngressRule = namedtuple('SecurityGroupIngressRule', ['rule_id', 'protocol', 'from_port', 'to_port', 'from_cidrv4', 'from_sg'])

SecurityGroupEgressRule = namedtuple('SecurityGroupEgressRule', ['rule_id', 'protocol', 'from_port', 'to_port', 'cidr_ipv4', 'cidr_ipv6'])

