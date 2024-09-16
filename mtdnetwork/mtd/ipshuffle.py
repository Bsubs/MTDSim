from mtdnetwork.mtd import MTD
from mtdnetwork.component import host
import random


class IPShuffle(MTD):

    def __init__(self, network=None):
        super().__init__(name="IPShuffle",
                         mtd_type='shuffle',
                         resource_type='network',
                         network=network)

    def mtd_operation(self, adversary=None):
        # Get all hosts in the network
        hosts = self.network.get_hosts()

        # Find the host with IP "192.168.0.128" to start the traversal
        starting_host = None
        for host_id, host_instance in hosts.items():
            if host_instance.get_ip() == "192.168.0.128":
                starting_host = host_id
                break

        if starting_host is None:
            raise ValueError("Starting IP address '192.168.0.128' not found in the network.")

        # Perform BFS or DFS to find all reachable hosts from the starting host
        visited = set()
        to_visit = [starting_host]
        cluster_hosts = []

        while to_visit:
            current_host_id = to_visit.pop()
            if current_host_id not in visited:
                visited.add(current_host_id)
                cluster_hosts.append(current_host_id)
                neighbors = self.network.get_neighbors(current_host_id)
                for neighbor in neighbors:
                    if neighbor not in visited:
                        to_visit.append(neighbor)

        # Gather IPs of all hosts in the cluster
        ip_addresses = [hosts[host_id].get_ip() for host_id in cluster_hosts]

        # Shuffle the IPs
        random.shuffle(ip_addresses)

        # Reallocate the shuffled IPs back to the hosts
        for host_id, new_ip in zip(cluster_hosts, ip_addresses):
            hosts[host_id].ip = new_ip
