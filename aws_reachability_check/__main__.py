import argparse
import sys

from . import core
from .aws import from_lambda, to_rds


arg_parser = argparse.ArgumentParser(description="Determines whether one AWS resource can connect to another")
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

try:
    if args.fromLambda:
        svc_from = from_lambda.lookup(args.fromLambda)
    if args.toRDS:
        svc_to = to_rds.lookup(args.toRDS)
except:
    print(sys.exc_info()[1])
    sys.exit(2)
    
# print(f"From: {svc_from}")
# print(f"To:   {svc_to}")

if svc_from.vpc == svc_to.vpc:
    print("in same VPC")
else:
    # TODO - a better connectivity test; checking for Internet access
    print("not in same VPC")
    sys.exit(3)
    
