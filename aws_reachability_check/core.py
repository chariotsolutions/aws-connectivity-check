""" Defines core data classes for the reachability analyzer.
    """

from collections import namedtuple

FromInfo = namedtuple('FromInfo', ['resource_type', 'resource_name', 'vpc', 'subnet_ids', 'security_group_ids', 'cidr'])

ToInfo = namedtuple('ToInfo', ['resource_type', 'resource_name', 'vpc', 'subnet_ids', 'security_group_ids', 'cidr', 'port'])

Subnet = namedtuple('Subnet', ['vpc_id', 'subnet_id', 'cidr', 'availability_zone', 'route_table', 'access_to_internet'])

RouteTable = namedtuple('RouteTable', ['vpc_id', 'route_table_id', 'gateway'])
