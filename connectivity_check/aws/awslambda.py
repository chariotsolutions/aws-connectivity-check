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
