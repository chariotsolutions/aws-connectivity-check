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


""" Code to retrieve information about security groups and determine connectivity
    between resources based on those groups.
    """

import boto3
import ipaddress

from collections import namedtuple
from functools import lru_cache

##
## Abstract representation of security group rules
##

class SecurityGroupRule:
    """ Common information for ingress rules and egress rules.
        """
    
    def __init__(self, group_id, group_name, rule_id, protocol, from_port, to_port):
        self.group_id = group_id
        self.group_name = group_name
        self.rule_id = rule_id
        self.protocol = protocol
        self.from_port = 0 if from_port == -1 else from_port
        self.to_port = 65535 if to_port == -1 else to_port
        
    def check_port(self, dest_port):
        # TODO - check protocol
        dest_port = int(dest_port) # we get from args as string
        return dest_port >= self.from_port and dest_port <= self.to_port
        
              
class SecurityGroupEgressRule(SecurityGroupRule):
    """ Information/checks specific to egress rules.
        """
    
    # TODO - support IPv6
    def __init__(self, group_id, group_name, rule_id, protocol, from_port, to_port, cidr_ipv4, cidr_ipv6):
        super().__init__(group_id, group_name, rule_id, protocol, from_port, to_port)
        self.cidr_ipv4 = cidr_ipv4
        self.addr_ipv4 = ipaddress.ip_network(cidr_ipv4) if cidr_ipv4 else None
        
    def check(self, dest_cidr, port, evaluation):
        if self.addr_ipv4:
            dst_addr = ipaddress.ip_network(dest_cidr)
            if dst_addr.subnet_of(self.addr_ipv4) and self.check_port(port):
                return True
            elif dst_addr.subnet_of(self.addr_ipv4):
                evaluation.add_context(f"egress rule {self.rule_id} allows {dest_cidr} but not port {port}")
                return False
            else:
                return False
                
        
class SecurityGroupIngressRule(SecurityGroupRule):
    """ Information/checks specific to ingress rules.
        """
    
    # TODO - support IPv6
    def __init__(self, group_id, group_name, rule_id, protocol, from_port, to_port, src_group_id, src_cidr_ipv4, src_cidr_ipv6):
        super().__init__(group_id, group_name, rule_id, protocol, from_port, to_port)
        self.src_group_id = src_group_id
        self.src_cidr_ipv4 = src_cidr_ipv4
        self.src_addr_ipv4 = ipaddress.ip_network(src_cidr_ipv4) if src_cidr_ipv4 else None
        
    def check(self, src_group_id, src_cidr_ipv4, port, evaluation):
        if self.src_group_id and src_group_id:
            if self.src_group_id == src_group_id and self.check_port(port):
                evaluation.mark_success(f"{self.group_id} has group-based rule {self.rule_id} that allows {src_group_id} on port {port}")
                return True
            elif self.src_group_id == src_group_id:
                evaluation.add_context(f"{self.group_id} has group-based rule {self.rule_id} that allows {src_group_id} but not on port {port}")
        if self.src_addr_ipv4 and src_cidr_ipv4:
            src_addr_ipv4 = ipaddress.ip_network(src_cidr_ipv4)
            if src_addr_ipv4.subnet_of(self.src_addr_ipv4) and self.check_port(port):
                evaluation.mark_success(f"{self.group_id} has cidr-based rule {self.rule_id} that allows {src_cidr_ipv4} on port {port}")
                return True
            elif src_addr_ipv4.subnet_of(self.src_addr_ipv4):
                evaluation.add_context(f"{self.group_id} has cidr-based rule {self.rule_id} that allows {src_cidr_ipv4} but not on port {port}")
        return False


class SecurityGroupRules:
    """ Maintains information about the ingress and egress rules for a set of
        security groups, and exposes a connection evaluator.
        
        The assumption underlying this object is that it will be used to hold
        either the egress rules for a source group, or the ingress rules for
        a destination group, not both.
        """

    def __init__(self):
        self.src_group_ids = set()
        self.egress_rules = []
        self.ingress_rules = []

    def add_egress_rule(self, group_id, group_name, rule_id, protocol, from_port, to_port, cidr_ipv4, cidr_ipv6):
        self.src_group_ids.add(group_id)
        self.egress_rules.append(
            SecurityGroupEgressRule(group_id, group_name, rule_id, protocol, from_port, to_port, cidr_ipv4, cidr_ipv6))
        return self

    def add_ingress_rule(self, group_id, group_name, rule_id, protocol, from_port, to_port, src_group_id, src_cidr_ipv4, src_cidr_ipv6):
        self.ingress_rules.append(
            SecurityGroupIngressRule(group_id, group_name, rule_id, protocol, from_port, to_port, src_group_id, src_cidr_ipv4, src_cidr_ipv6))
        return self

    def can_connect_to(self, src_cidr, dest_cidr, dest_port, dest_rules):
        """ Determines whether a resource with the given source CIDR can connect
            to a resource at the specified destination cidr and port that has the
            specified set of rules.

            The result can either be definitive success, definitive failure, or a
            partial misconfiguration (eg, destination allows source security group
            but not desired port).

            If there are multiple valid connection paths, returns one arbitrarily.
            """
        evaluation = ConnectivityEvaluation()
        self._check_egress_rules(dest_cidr, dest_port, evaluation)
        if evaluation.failure:
            return evaluation
        self._check_ingress_rules(src_cidr, dest_port, dest_rules, evaluation)
        return evaluation
    
    def _check_egress_rules(self, dest_cidr, dest_port, evaluation):
        for rule in self.egress_rules:
            if rule.check(dest_cidr, dest_port, evaluation):
                return
        evaluation.failure = f"no egress rule allows connections to {dest_cidr} port {dest_port}"            

    def _check_ingress_rules(self, src_cidr, dest_port, dest_rules, evaluation):
        for src_group_id in self.src_group_ids:
            for rule in dest_rules.ingress_rules:
                if rule.check(src_group_id, src_cidr, dest_port, evaluation):
                    return
            

class ConnectivityEvaluation:
    """ Tracks the definitive success/failure of an evaluated connection,
        along with additional context for "near misses".
        """

    def __init__(self):
        self.success = None
        self.failure = None
        self.context = set()

    def mark_success(self, msg):
        self.success = msg

    def mark_failure(self, msg):
        self.failure = msg

    def add_context(self, msg):
        self.context.add(msg)

##
## Retrieval of actual security group rules
##

@lru_cache(maxsize=1)
def _ec2_client():
    return boto3.client('ec2')


def lookup(security_group_ids):
    """ Given a (possibly empty) list of security groups, retrieves and combines
        the rules associated with those groups.
        """
    result = SecurityGroupRules()
    if not security_group_ids:
        return result
    for sg in _ec2_client().describe_security_groups(GroupIds=security_group_ids)['SecurityGroups']:
        group_id = sg['GroupId']
        group_name = sg['GroupName']
        for sgr in _ec2_client().describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [group_id]}])['SecurityGroupRules']:
            rule_id = sgr['SecurityGroupRuleId']
            protocol = sgr['IpProtocol']
            from_port = int(sgr['FromPort'])
            to_port = int(sgr['ToPort'])
            if sgr['IsEgress']:
                cidr_ipv4 = sgr.get('CidrIpv4')
                cidr_ipv6 = sgr.get('CidrIpv6')
                result.add_egress_rule(group_id, group_name, rule_id, protocol, from_port, to_port, cidr_ipv4, cidr_ipv6)
            else:
                src_group_id = sgr.get('ReferencedGroupInfo', {}).get('GroupId')
                src_cidr_ipv4 = sgr.get('CidrIpv4')
                src_cidr_ipv6 = sgr.get('CidrIpv6')
                result.add_ingress_rule(group_id, group_name, rule_id, protocol, from_port, to_port, src_group_id, src_cidr_ipv4, src_cidr_ipv6)
    return result
