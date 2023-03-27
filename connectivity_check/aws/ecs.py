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


""" Code to retrieve information about ECS Services.
    """

import boto3
import re

from collections import namedtuple
from functools import lru_cache

from ..core import FromInfo
from .vpc import lookup_by_subnet as vpc_lookup


def lookup_from(service_name):
    """ This is the entry point for retrieving information about an ECS service as a source.
        It may be passed a simple name, for services running in the default cluster, or a
        "cluster:service" identifier.
        """
    names = re.match(r'((?P<cluster_name>[^:]+):)?(?P<service_name>.+)', service_name)
    if not names:
        raise Exception(f"unable to parse ECS service specification: {service_name}")
    if names.group('cluster_name'):
        resp = _ecs_client().describe_services(cluster=names.group('cluster_name'), services=[names.group('service_name')])
    else:
        resp = _ecs_client().describe_services(services=[names.group('service_name')])
    if len(resp['services']) > 0:
        desc = resp['services'][0]
    else:
        raise Exception(f"unable to find service {service_name}")
    network_config = desc['networkConfiguration']['awsvpcConfiguration']
    subnet_ids = network_config['subnets']
    security_group_ids = network_config['securityGroups']
    vpc = vpc_lookup(subnet_ids[0])
    cidr = vpc.subnets[subnet_ids[0]].cidr
    return FromInfo("ECS", desc['serviceName'], vpc, subnet_ids, security_group_ids, cidr)
        
        
##
## Internals
##

@lru_cache(maxsize=1)
def _ecs_client():
    return boto3.client('ecs')
