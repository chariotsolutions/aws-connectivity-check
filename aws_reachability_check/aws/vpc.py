""" Retrieves information about a VPC, which can then be used to test connectivity
    between the "from" and "to" VPCs.
    """

import boto3
import ipaddress

from collections import namedtuple
from functools import lru_cache


def lookup(vpc_id):
    """ This is the primary entry point: it's passed a VPC ID, which may be None,
        and returns an object that can be used to check connectivity.
        """
    return Vpc(vpc_id)
    
    
class Vpc:
    """ Maintains information about a VPC, and methods to determine whether
        two VPCs are connected.
        """
    
    def __init__(self, vpc_id):
        self.vpc_id = vpc_id
        
        
##
## Internals
##

