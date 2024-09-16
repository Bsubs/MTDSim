from mtdnetwork.mtd import MTD
import networkx as nx
import random


class CompleteTopologyShuffle(MTD):
    """
    Completely regenerates the network, preserving the hosts from previously.
    """

    def __init__(self, network=None):
        super().__init__(name="CompleteTopologyShuffle",
                         mtd_type='shuffle',
                         resource_type='network',
                         network=network)
        
    def _shuffle_edges_with_connectivity(self, subgraph, original_edges, start_host_id):
        nodes = list(subgraph.nodes())
        shuffled_edges = set()

        # First, create a minimum spanning tree to ensure all nodes are connected
        mst_edges = list(nx.minimum_spanning_edges(subgraph, algorithm="kruskal", data=False))

        # Add the MST edges to the shuffled set
        for edge in mst_edges:
            shuffled_edges.add(edge)

        remaining_edges = len(original_edges) - len(mst_edges)
        
        # Shuffle remaining edges and add them ensuring no duplicates
        while len(shuffled_edges) < len(original_edges):
            u, v = random.sample(nodes, 2)
            if (u, v) not in shuffled_edges and (v, u) not in shuffled_edges:
                shuffled_edges.add((u, v))

        # Ensure node 0 is connected (redundant but double-check)
        if not any(edge for edge in shuffled_edges if start_host_id in edge):
            # Randomly connect node 0 to another node if it's not already connected
            target_node = random.choice([n for n in nodes if n != start_host_id])
            shuffled_edges.add((start_host_id, target_node))

        # Final connectivity check
        shuffled_subgraph = nx.Graph()
        shuffled_subgraph.add_edges_from(shuffled_edges)
        if not nx.is_connected(shuffled_subgraph):
            raise RuntimeError("The shuffled subgraph is not connected. An error occurred in the shuffling process.")

        return list(shuffled_edges)

    def mtd_operation(self, adversary=None):
        hosts = self.network.get_hosts()

        # Find the host with IP "192.168.0.128"
        start_host_id = None
        for host_id, host_instance in hosts.items():
            if host_instance.get_ip() == "192.168.0.128":
                start_host_id = host_id
                break

        if start_host_id is None:
            raise ValueError("Host with IP '192.168.0.128' not found in the network")

        # Perform BFS/DFS to find all reachable hosts within the cluster
        reachable_hosts = set()
        stack = [start_host_id]

        while stack:
            current_host = stack.pop()
            if current_host not in reachable_hosts:
                reachable_hosts.add(current_host)
                neighbors = self.network.get_neighbors(current_host)
                stack.extend(neighbors)

        # Extract the subgraph of reachable hosts
        subgraph = self.network.graph.subgraph(reachable_hosts).copy()

        # Get the list of edges in the subgraph
        edges = list(subgraph.edges())

        # Ensure node 0 (or starting node) remains connected
        if start_host_id not in subgraph.nodes:
            raise ValueError(f"Start host {start_host_id} (IP '192.168.0.128') is not in the subgraph.")

        # Shuffle edges but ensure connectivity and inclusion of node 0
        shuffled_edges = self._shuffle_edges_with_connectivity(subgraph, edges, start_host_id)

        # Clear original edges in the cluster from the main graph
        self.network.graph.remove_edges_from(edges)

        # Add the shuffled edges back to the main graph
        self.network.graph.add_edges_from(shuffled_edges)

        # Update reachable nodes and attack path exposure
        self.network.update_reachable_mtd()
        if self.network.get_network_type() == 0:
            self.network.add_attack_path_exposure()

    
