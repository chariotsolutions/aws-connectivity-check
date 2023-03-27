""" Code to retrieve information about VPCs and determine whether one VPC has
    connectivity to another.
    """

import boto3
import ipaddress

from functools import lru_cache

from ..core import Subnet, RouteTable


def lookup(vpc_id):
    """ Retrieves the provided VPC and related information. If passed None,
        returns a "null object" that can interact with other VPC objects.
        """
    if vpc_id:
        vpc = _describe_vpc(vpc_id)
        route_tables_by_subnet = _describe_route_tables_by_subnet(vpc_id)
        subnets = _describe_subnets(vpc_id, route_tables_by_subnet)
        return Vpc(vpc_id, subnets, route_tables_by_subnet)
    else:
        return Vpc(None, None, None)
    
    
def lookup_by_subnet(subnet_id):
    """ Retrieves VPC information given the ID of one of its subnets.
        This is used to retrieve information about ECS services, which
        don't provide the VPC in their description.
        """
    subnet_desc = _ec2_client().describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
    return lookup(subnet_desc['VpcId'])


class Vpc:
    """ Maintains information about a VPC, and methods to determine whether
        two VPCs are connected.
        """

    def __init__(self, vpc_id, subnets, route_tables_by_subnet):
        self.vpc_id = vpc_id
        self.subnets = subnets
        self.route_tables_by_subnet = route_tables_by_subnet

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.vpc_id == other.vpc_id
        else:
            return False


##
## Internals
##

@lru_cache(maxsize=1)
def _ec2_client():
    return boto3.client('ec2')


@lru_cache(maxsize=1)
def vpc_filter(vpc_id):
    return [{'Name': "vpc-id", 'Values': [vpc_id]}]


def _describe_vpc(vpc_id):
    vpcs = _ec2_client().describe_vpcs(VpcIds=[vpc_id])['Vpcs']
    return vpcs[0]


def _describe_subnets(vpc_id, route_table_lookup):
    result = {}
    subnets = _ec2_client().describe_subnets(Filters=vpc_filter(vpc_id))['Subnets']
    subnets = sorted(subnets, key=lambda s: ipaddress.IPv4Network(s['CidrBlock']))
    for subnet in subnets:
        subnet_id = subnet['SubnetId']
        cidr = subnet['CidrBlock']
        az = subnet['AvailabilityZone']
        route_table = route_table_lookup.get(subnet_id, {})
        route_table_id = route_table and route_table.route_table_id or None
        gateway = route_table and route_table.gateway or None
        result[subnet_id] = Subnet(vpc_id, subnet_id, cidr, az, route_table_id, gateway)
    return result


def _describe_route_tables_by_subnet(vpc_id):
    result = {}
    route_tables = _ec2_client().describe_route_tables(Filters=vpc_filter(vpc_id))['RouteTables']
    for rt in route_tables:
        gateway = None
        for route in rt.get('Routes', []):
            if route.get('DestinationCidrBlock') == "0.0.0.0/0":
                gateway = route.get('GatewayId', route.get('NatGatewayId'))
        rt2 = RouteTable(vpc_id, rt['RouteTableId'], gateway)
        for assoc in rt.get('Associations', []):
            subnet_id = assoc.get('SubnetId')
            state = assoc.get('AssociationState', {}).get('State')
            if state == "associated":
                result[subnet_id] = rt2
    return result