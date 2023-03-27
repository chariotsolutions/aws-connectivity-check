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


import argparse
import sys

from . import core
from .aws import awslambda, ecs, rds, security_groups


arg_parser = argparse.ArgumentParser(description="Determines whether one AWS resource can connect to another")
arg_parser.add_argument("--fromECS",
                        metavar="SERVICE_NAME",
                        dest='fromECS',
                        help="""The Fargate ECS Service that is trying to make a connection. Can be specified via
                                either name alone (for the default cluster) or CLUSTER:NAME.
                                """)
arg_parser.add_argument("--fromLambda",
                        metavar="LAMBDA_NAME",
                        dest='fromLambda',
                        help="""The Lambda function that is trying to make a connection. Can be specified via
                                either name or ARN.
                                """)
arg_parser.add_argument("--toRDS",
                        metavar="INSTANCE_NAME",
                        dest='toRDS',
                        help="""The name of an RDS instance or cluster. If given a cluster name, will use the
                                writer instance if necessary.
                                """)
arg_parser.add_argument("--port",
                        metavar="PORT_NUMBER",
                        dest='port',
                        default=5432,
                        help="""The port number used for connections. If omitted, defaults to 5432
                                """)
args = arg_parser.parse_args()

svc_from = None
svc_to = None

print("loading service information")
try:
    if args.fromECS:
        svc_from = ecs.lookup_from(args.fromECS)
    if args.fromLambda:
        svc_from = awslambda.lookup_from(args.fromLambda)
    if args.toRDS:
        svc_to = rds.lookup_to(args.toRDS)
except:
    print(sys.exc_info()[1])
    sys.exit(2)
    
# print(f"From: {svc_from}")
# print(f"To:   {svc_to}")

print("checking VPC connectivity")
if svc_from.vpc == svc_to.vpc:
    print("* in same VPC")
else:
    # TODO - a better connectivity test; checking for Internet access
    print("* not in same VPC")
    sys.exit(3)
    
print("checking security groups")
from_sg_rules = security_groups.lookup(svc_from.security_group_ids)
to_sg_rules = security_groups.lookup(svc_to.security_group_ids)
analysis = from_sg_rules.can_connect_to(svc_from.cidr, svc_to.cidr, args.port, to_sg_rules)
if analysis.success:
    print(f"* {analysis.success}")
elif analysis.failure:
    print(f"* {analysis.failure}")
    sys.exit(3)
elif analysis.context:
    for msg in analysis.context:
        print(f"* {msg}")
    sys.exit(3)
    
    
