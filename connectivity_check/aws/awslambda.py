""" Code to retrieve information about Lambdas. Named "awslambda" because "lambda"
    is a reserved word in Python.
    """

import boto3

from collections import namedtuple
from functools import lru_cache

from ..core import FromInfo
from .vpc import lookup as vpc_lookup


def lookup_from(lambda_name):
    """ This is the entry point for retrieving information about Lambda as a source.
        It may be passed the function's name or ARN.
        """
    lambda_config = _lambda_client().get_function(FunctionName=lambda_name)['Configuration']
    vpc_config = lambda_config.get('VpcConfig')
    if vpc_config:
        vpc_id = vpc_config.get('VpcId')
        subnet_ids = vpc_config.get('SubnetIds')
        security_group_ids = vpc_config.get('SecurityGroupIds')
        vpc = vpc_lookup(vpc_id)
        cidr = vpc.subnets[subnet_ids[0]].cidr
    else:
        # TODO - support for non-VPC Lambdas
        raise Exception("this tool does not currently support Lambdas that don't run in a VPC")
    return FromInfo("lambda", lambda_config['FunctionName'], vpc, subnet_ids, security_group_ids, cidr)
        
        
##
## Internals
##

@lru_cache(maxsize=1)
def _lambda_client():
    return boto3.client('lambda')
