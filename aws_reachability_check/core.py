""" Defines core data classes for the reachability analyzer.
    """

from collections import namedtuple

FromDesc = namedtuple('FromDesc', ['resource'])

ToDesc = namedtuple('ToDesc', ['resource'])