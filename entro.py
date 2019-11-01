#!/usr/bin/env python
import sys
import socket
import subprocess
import os


vagrant_machines_dir = os.path.join(os.getcwd(), ".vagrant", "machines")
if not os.path.exists(vagrant_machines_dir):
    raise RuntimeError(vagrant_machines_dir + "doesn't exist")

all_hosts = set(os.listdir(vagrant_machines_dir))
all_ips = {}
for host in all_hosts:
    try:
        ip = socket.gethostbyname(host)
        all_ips[host] = ip
        print(host + " -> " + ip)
    except socket.gaierror:
        print("Cannot find ip for host " + host + ", skipping")


def validate_host(host):
    if host not in all_hosts:
        raise Exception("Host " + host + " is not in " + str(all_hosts))


def validate_hosts(hosts):
    for host in hosts:
        validate_host(host)


class BlockTcpPacketsAction(object):
    def __init__(self, on_host, block_hosts):
        self.on_host = on_host  # type: str
        self.block_hosts = block_hosts  # type: List[str]

    @staticmethod
    def do_func():
        pass

    @staticmethod
    def undo_func():
        pass

    def __str__(self):
        return "Block TCP packets to and from " + str(self.block_hosts) + " on host " + self.on_host

    def do(self):
        self.do_func(self.on_host, self.block_hosts)

    def undo(self):
        try:
            self.undo_func(self.on_host, self.block_hosts)
        except Exception as e:
            print('Caught ' + str(e) + ' but ignoring to make undo idempotent')


def vagrant_ssh(command, on_host):
    print("Going to call " + command + " on Vagrant VM " + on_host)
    subprocess.call(["vagrant", "ssh", "-c", command, on_host])


def iptables_block_tcp_packets_commands(blocked_host):
    blocked_ip = all_ips[blocked_host]
    block_incoming = "sudo -u root iptables -A INPUT -s " + blocked_ip + " -j DROP"
    block_outgoing = "sudo -u root iptables -A OUTPUT -d " + blocked_ip + " -j DROP"
    return [block_incoming, block_outgoing]


def block_tcp_packets_with_vagrant_ssh_iptables(on_host, blocked_hosts):
    for blocked_host in blocked_hosts:
        for command in iptables_block_tcp_packets_commands(blocked_host):
            vagrant_ssh(command, on_host)


BlockTcpPacketsAction.do_func = staticmethod(block_tcp_packets_with_vagrant_ssh_iptables)


def iptables_unblock_tcp_packets_commands(unblocked_host):
    unblocked_ip = all_ips[unblocked_host]
    unblock_incoming = "sudo -u root iptables -D INPUT -s " + unblocked_ip + " -j DROP"
    unblock_outgoing = "sudo -u root iptables -D OUTPUT -d " + unblocked_ip + " -j DROP"
    return [unblock_incoming, unblock_outgoing]


def unblock_tcp_packets_with_vagrant_ssh_iptables(on_host, unblocked_hosts):
    for unblocked_host in unblocked_hosts:
        for command in iptables_unblock_tcp_packets_commands(unblocked_host):
            vagrant_ssh(command, on_host)


BlockTcpPacketsAction.undo_func = staticmethod(unblock_tcp_packets_with_vagrant_ssh_iptables)


def compute_block_tcp_packets_actions(partitions):
    actions = []
    for partitioned_hosts in partitions:
        validate_hosts(partitioned_hosts)
        blocked_hosts = sorted(all_hosts.difference(partitioned_hosts))
        for partitioned_host in partitioned_hosts:
            actions.append(BlockTcpPacketsAction(
                partitioned_host,
                blocked_hosts
            ))
    return actions


def print_usage():
    print("""
Easily create network chaos among your Vagrant VMs

Usage:
    ./entro.py
        Print this message
    ./entro.py partition vm1
        Block all incoming TCP packets into vm1 from all other hosts
        Block all outgoing TCP packets from vm1 to all other hosts
    ./entro.py partition vm1,vm2
        Block all incoming TCP packets into vm1 from all other hosts except for vm2
        Block all outgoing TCP packets from vm1 to all other hosts except for vm2
        Block all incoming TCP packets into vm2 from all other hosts except for vm1
        Block all outgoing TCP packets from vm2 to all other hosts except for vm1
    ./entro.py partition vm1 vm2,vm5
        Block all incoming TCP packets into vm1 from all other hosts
        Block all outgoing TCP packets from vm1 to all other hosts
        Block all incoming TCP packets into vm2 from all other hosts except for vm5
        Block all outgoing TCP packets from vm2 to all other hosts except for vm5
        Block all incoming TCP packets into vm5 from all other hosts except for vm2
        Block all outgoing TCP packets from vm5 to all other hosts except for vm2
    ./entro.py unpartition vm1
        Revert what is done by "./entro.py partition vm1"
    ./entro.py unpartition vm1,vm2
        Revert what is done by "./entro.py partition vm1,vm2"
    ./entro.py unpartition vm1 vm2,vm5
        Revert what is done by "./entro.py partition vm1 vm2,vm5"
""".strip())
    sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print_usage()

    verb = sys.argv[1]
    if verb not in ["partition", "unpartition"]:
        print_usage()

    if verb == "partition":
        partitions = [partition.split(",") for partition in sys.argv[2:]]
        for action in compute_block_tcp_packets_actions(partitions):
            action.do()

    if verb == "unpartition":
        partitions = [partition.split(",") for partition in sys.argv[2:]]
        for action in compute_block_tcp_packets_actions(partitions):
            action.undo()
