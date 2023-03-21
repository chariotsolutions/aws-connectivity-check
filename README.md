# aws-connectivity-check

This is a tool to determine whether one AWS resource (such as a Lambda) can connect
to another (such as RDS), based on network routing and security groups. It is intended
to identify common problems that we've seen in workshops and trainings, not be a replacement
for the [AWS Reachability Analyzer](https://docs.aws.amazon.com/vpc/latest/reachability/what-is-reachability-analyzer.html).

Currently supports the following:

* From: Lambda 
* To: RDS
* Resources must be in the same VPC.
* Security groups must be based on CIDR or referenced security group.


## Running

This tool requires `boto3` to run. If you do not have it centrally installed, use
a virtual environment or install into a directory referenced by `PYTHONPATH`.

The general form for commands is to specify a "from" and "to" resource, using a
specified port. For example, to verify a connection from a Lambda to an RDS instance
running MySQL, you would use a command like the following:

```
python -m connectivity_check --fromLambda MyExampleLambda --toRDS MyExampleDatabase --port 3306
```

The tool performs a series of checks, and reports its findings:

```
loading service information
checking VPC connectivity
* in same VPC
checking security groups
* sg-088d916b60f1d730b has group-based rule sgr-04d8d665137cdf8b3 that allows sg-00160a4c50a2fbc93 but not on port 3306
```

In this case, the Lambda can't connect to the database because no security group has
a rule that allows connections from the Lambda on port 3306. However, there is a
security group that allows connections on port 5432, which indicates that maybe it's
misconfigured (or intentionally supports Postgres but not MySQL).


## Command-line Options (supported resources)

The resource parameters all take the from of `--from` or `--to`, followed by an AWS
Service name. Each requires a resource identifier, which can take different forms
depending on the service.


| Parameter                   | Resource Identifier / Argument          |
|-----------------------------|-----------------------------------------|
| `--port`                    | Port number for connection.             |
| `--fromLambda`              | Function name or ARN.                   |
| `--toRDS`                   | Instance or cluster name                |


## How it works

### Handling different resource types

Every resource type has its own API calls to retrieve information about the resource.
However, they all provide similar information, which the program captures using the
`FromInfo` and `ToInfo` named tuples, defined in the `core` module.

Each supported resource type has a module to retrieve the appropriate information. The
program can then use common code to evaluate connectivity.


### IP Addresses

To check whether a CIDR-based security group rule allows an incoming connection, you need
to know the source IP address. However, the connection between a resource and its actual
IP address may not be easy to discover: an in-VPC Lambda, for example, uses a network
interface that's associated with the same subnets and security groups as the Lambda itself,
but there's no way to get the actual ENI from the Lambda configuration.

Therefore, I take a simplified approach: if I know the resource CIDR exactly, I'll use it.
If not, I pick the CIDR associated with one of the subnets where the resource runs. This
is not perfect: you can define a security group that allows access from one subnet but
blocks another, but this is an unusual occurrence.
