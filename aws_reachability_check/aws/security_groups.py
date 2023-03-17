""" Code to retrieve information about security groups and determine connectivity
    between resources based on those groups.
    """

import boto3
import ipaddress

from collections import namedtuple
from functools import lru_cache

from ..core import SecurityGroupIngressRule, SecurityGroupEgressRule


def lookup(security_group_ids):
    """ Given a (possibly empty) list of security groups, looks up the rules
        associated with those groups and wraps them in an object.
        """
    result = SecurityGroups()
    if not security_group_ids:
        return result
    for sg in _ec2_client().describe_security_groups(GroupIds=security_group_ids)['SecurityGroups']:
        group_id = sg['GroupId']
        result.add_security_group(group_id, sg['GroupName'])
        _retrieve_rules(result, group_id)
    return result


class SecurityGroups:
    """ Maintains information about a set of security groups, and evaluates
        connectivity to a different set.
        """

    def __init__(self):
        self.security_group_ids = set()
        self.security_group_names = {}
        self.ingress_rules_by_sg = {}
        self.egress_rules_by_sg = {}

    def add_security_group(self, security_group_id, security_group_name):
        self.security_group_ids.add(security_group_id)
        self.security_group_names[security_group_id] = security_group_name
        self.ingress_rules_by_sg[security_group_id] = []
        self.egress_rules_by_sg[security_group_id] = []
        return self

    def add_ingress_rule(self, security_group_id, rule):
        self.ingress_rules_by_sg[security_group_id].append(rule)
        return self

    def add_egress_rule(self, security_group_id, rule):
        self.egress_rules_by_sg[security_group_id].append(rule)
        return self

    def can_connect_to(self, src_cidr, dest_groups, dest_cidr, port):
        """ Determines whether a resource with the given source CIDR can connect
            to a resource at the specified destination cidr and port that has the
            specified set of rules.

            The result can either be definitive success, definitive failure, or a
            partial misconfiguration (eg, destination allows source security group
            but not desired port).

            If there are multiple valid connection paths, returns one arbitrarily.
            """
        evaluation = ConnectivityEvaluation()
        self._check_egress_rules(dest_cidr, port, evaluation)
        if evaluation.failure:
            return evaluation
        for src_group_id in self.security_group_ids:
            self._check_ingress_by_referenced_group(src_group_id, dest_groups, port, evaluation)
            if evaluation.success:
                return evaluation
            self._check_ingress_by_cidr(src_cidr, dest_groups, port, evaluation)
            if evaluation.success:
                return evaluation
        return evaluation
    
    def _check_egress_rules(self, dest_cidr, port, evaluation):
        dst_addr = ipaddress.ip_network(dest_cidr)
        for src_group_id, rules in self.egress_rules_by_sg.items():
            for rule in rules:
                if rule.cidr_ipv4:
                    egress_addr = ipaddress.ip_network(rule.cidr_ipv4)
                    if dst_addr.subnet_of(egress_addr) and port_in_range(port, rule):
                        return evaluation
                    elif dst_addr.subnet_of(egress_addr):
                        evaluation.add_context(f"egress rule {rule.rule_id} allows {dest_cidr} but not port {port}")
        evaluation.failure = f"no egress rule allows connections to {dest_cidr} port {port}"
        return evaluation
            

    def _check_ingress_by_referenced_group(self, src_group_id, dest_groups, port, evaluation):
        for dest_group_id, rules in dest_groups.ingress_rules_by_sg.items():
            for rule in rules:
                if rule.from_sg == src_group_id:
                    if rule.from_port <= port and rule.to_port >= port:
                        evaluation.mark_success(f"{dest_group_id} has group-based rule {rule.rule_id} that allows {src_group_id} on port {port}")
                        return evaluation
                    else:
                        evaluation.add_context(f"{dest_group_id} has group-based rule {rule.rule_id} that allows {src_group_id} but not on port {port}")
        return evaluation

    def _check_ingress_by_cidr(self, src_cidr, dest_groups, port, evaluation):
        src_addr = ipaddress.ip_network(src_cidr)
        for dest_group_id, rules in dest_groups.ingress_rules_by_sg.items():
            for rule in rules:
                if rule.from_cidrv4:
                    dst_addr = ipaddress.ip_network(rule.from_cidrv4)
                    if src_addr.subnet_of(dst_addr) and rule.from_port <= port and rule.to_port >= port:
                        evaluation.mark_success(f"{dest_group_id} has cidr-based rule {rule.rule_id} that allows {src_cidr} on port {port}")
                        return evaluation
                    elif src_addr.subnet_of(dst_addr):
                        evaluation.add_context(f"{dest_group_id} has cidr-based rule {rule.rule_id} that allows {src_cidr} but not on port {port}")
        return evaluation


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
## Internals
##

@lru_cache(maxsize=1)
def _ec2_client():
    return boto3.client('ec2')


def _retrieve_rules(aggregator, group_id):
    for sgr in _ec2_client().describe_security_group_rules(Filters=[{'Name': 'group-id', 'Values': [group_id]}])['SecurityGroupRules']:
        rule_id = sgr['SecurityGroupRuleId']
        protocol = sgr['IpProtocol']
        from_port = int(sgr['FromPort'])
        if from_port == -1:
            from_port = 0
        to_port = int(sgr['ToPort'])
        if to_port == -1:
            to_port = 65535
        if sgr['IsEgress']:
            cidr_ipv4 = sgr.get('CidrIpv4')
            cidr_ipv6 = sgr.get('CidrIpv6')
            aggregator.add_egress_rule(group_id, SecurityGroupEgressRule(rule_id, protocol, from_port, to_port, cidr_ipv4, cidr_ipv6))
        else:
            from_cidrv4 = sgr.get('CidrIpv4')
            from_sg = sgr.get('ReferencedGroupInfo', {}).get('GroupId')
            aggregator.add_ingress_rule(group_id, SecurityGroupIngressRule(rule_id, protocol, from_port, to_port, from_cidrv4, from_sg))


def port_in_range(port, rule):
    return port >= rule.from_port and port <= rule.to_port