""" Code to retrieve information about an RDS database participating in the "to"
    side of a relationship.
    """

import boto3
import sys

from collections import namedtuple
from functools import lru_cache

from ..core import ToInfo
from .vpc import lookup as vpc_lookup


def lookup(rds_name):
    """ This is the entry point: it's passed either the name or ARN of a Lambda, 
        and returns information about that Lambda's outbound connectivity. If the
        Lambda doesn't exist, it will throw.
        """
    try:
        return _try_to_retrieve_instance(rds_name)
    except:
        try:
            return _try_to_retrieve_cluster_instance(rds_name)
        except:
            raise Exception(f"failed to find RDS instance/cluster with name {rds_name}")
    
        
##
## Internals
##

@lru_cache(maxsize=1)
def _rds_client():
    return boto3.client('rds')


def _try_to_retrieve_instance(rds_name):
    info = _rds_client().describe_db_instances(DBInstanceIdentifier=rds_name)['DBInstances'][0]
    subnet_group = info['DBSubnetGroup']
    vpc_id = subnet_group['VpcId']
    vpc = vpc_lookup(vpc_id)
    subnet_ids = [sn['SubnetIdentifier'] for sn in subnet_group['Subnets'] if sn['SubnetStatus'] == 'Active']
    security_group_ids = [sg['VpcSecurityGroupId'] for sg in info['VpcSecurityGroups'] if sg['Status'] == 'active']
    cidr = vpc.subnets[subnet_ids[0]].cidr
    port = info['Endpoint']['Port']
    # FIXME - retrieve info for Vpc, Subnets, and Security Groups
    return ToInfo('RDS', rds_name, vpc, subnet_ids, security_group_ids, cidr, port)



def _try_to_retrieve_cluster_instance(rds_name):
    cluster_info = _rds_client().describe_db_clusters(DBClusterIdentifier=rds_name)['DBClusters'][0]
    for instance in cluster_info['DBClusterMembers']:
        if instance['IsClusterWriter']:
            return _try_to_retrieve_instance(instance['DBInstanceIdentifier'])
    raise Exception(f"cluster {rds_name} has no writer instance")
