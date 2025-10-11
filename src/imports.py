from collections import defaultdict
import os
from os.path import join as osp
import json
import datetime

from typing import List, Tuple

from pytricia import PyTricia
import gzip

from loguru import logger

logger.add("logs/rpki_tree_{time}.log", enqueue=True)


def calculate_end_ip(start_ip, num_ips):
    # Convert IP to integer
    start_parts = list(map(int, start_ip.split(".")))
    start_int = (
        (start_parts[0] << 24)
        | (start_parts[1] << 16)
        | (start_parts[2] << 8)
        | start_parts[3]
    )

    # Add range (minus 1 because the start IP is included)
    end_int = start_int + num_ips - 1

    # Convert back to IP address format
    end_parts = [
        (end_int >> 24) & 255,
        (end_int >> 16) & 255,
        (end_int >> 8) & 255,
        end_int & 255,
    ]

    return ".".join(map(str, end_parts))


def get_cidr(start_ip, end_ip=None, num_ips=None):
    if end_ip is None:
        end_ip = calculate_end_ip(start_ip, num_ips)
    # convert ip range to CIDR
    from ipaddress import summarize_address_range, ip_address

    return [
        str(x)
        for x in summarize_address_range(
            ip_address(start_ip),
            ip_address(end_ip),
        )
    ]
