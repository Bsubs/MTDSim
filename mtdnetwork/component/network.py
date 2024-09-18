import networkx as nx
import pkg_resources
import matplotlib.pyplot as plt
import numpy as np
import random
import mtdnetwork.data.constants as constants
import mtdnetwork.component.services as services
from mtdnetwork.component.host import Host
from mtdnetwork.statistic.scorer import Scorer
import os
import ipaddress
import pandas as pd


class Network:

    def __init__(self, total_nodes, total_endpoints, total_subnets, total_layers, total_database, target_layer=None,
                 users_to_nodes_ratio=constants.USER_TO_NODES_RATIO,
                 prob_user_reuse_pass=constants.USER_PROB_TO_REUSE_PASS, seed=None):
        """
        Initialises the state of the network for the simulation.

        Parameters:
            total_nodes:
                the number of the nodes in the network.
            total_endpoints:
                the number of nodes exposed on the internet (hacker can interact directly with them).
                total_endpoints must be less than total_nodes.
            total_subnets:
                how many subnets in the network.
            total_layers:
                how many layers deep from the exposed endpoints the network is.
            user_to_nodes_ratio:
                the percent of users in comparison to hsot machines.
                each node will then be given `int(1/user_to_nodes_ratio)` users each (less users more users on each computer).
            prob_user_reuse_pass:
                the probability that a user has reused their password.
            seed:
                the seed for the random number generator if one needs to be set
        """
        self.graph = None
        self.colour_map = []
        self.users_per_host = None
        self.total_users = None
        self.users_list = None
        self.pos = {}
        if seed is not None:
            random.seed(seed)
        self.total_nodes = total_nodes
        self.total_endpoints = total_endpoints
        self.total_subnets = total_subnets
        self.layers = total_layers
        self.exposed_endpoints = [n for n in range(total_endpoints)]

        self.total_database = total_database
        self._database = [n for n in range(total_nodes - total_database, total_nodes)]

        self.tags = []
        self.tag_priority = []
        self.service_generator = services.ServicesGenerator()
        self.nodes = [n for n in range(total_nodes)]
        self.mtd_strategies = []

        self.reachable = []
        self.compromised_hosts = []
        self.node_per_layer = []
        # Network type 0 is a targetted attack, Network type 1 is a general attack (no target node)
        self.network_type = 1
        self.vuln_dict = {}
        self.vuln_count = {}
        self.service_dict = {}
        self.service_count = {}
        self.total_vulns = 0
        self.total_services = 0
        self.scorer = Scorer()
        self.users_to_nodes_ratio = users_to_nodes_ratio
        self.prob_user_reuse_pass = prob_user_reuse_pass

        self.target_node = None
        self.target_layer = target_layer

    def init_network(self):
        self.assign_tags()
        self.assign_tag_priority()
        self.setup_users(self.users_to_nodes_ratio, self.prob_user_reuse_pass, constants.USER_TOTAL_FOR_EACH_HOST)
        self.gen_graph()
        # self.setup_network()
        # self.draw()
        self.scorer.set_initial_statistics(self)

    def update_host_information(self):
        """
        Updates the host
        """
        for host_id in self.nodes:
            host = self.get_host(host_id)
            host.swap_network(self)

    def gen_graph(self, min_nodes_per_subnet=2, max_subnets_per_layer=5, subnet_m_ratio=0.2,
                  prob_inter_layer_edge=0.4):
        """
        Generates a network of subnets using the Barabasi-Albert Random Graph model.

        Parameters:
            min_nodes_per_subnet:
                minimum number of computer nodes for each subnet
            max_subnets_per_layer:
                the maximum number of subnets per layer
            subnet_m_ratio:
                a ratio that is used to determine the parameter m for the barabasi albert graph.
                m is the number of edges to attach from a new node to existing nodes
            prob_inter_layer_edge:
                probability that a node connects to a different layer in the network.
        """

        # # Update Nodes Per Layer for Complete topology shuffling
        # self.node_per_layer = nodes_per_layer.copy()
        # self.node_per_layer[0] = self.total_endpoints

    ################################################################
        # FINALLLLLLLLLLLLLLLLLLLLLY

        # random.seed(4011)

        # Function to determine the layer of an IP address
        def classify_ip_type(ip):
            try:
                ip_addr = ipaddress.ip_address(ip)
                if ip_addr.is_private:
                    return 'private'
                elif ip_addr.is_loopback:
                    return 'special'
                elif ip_addr.is_multicast:
                    return 'special'
                elif ip_addr.is_reserved:
                    return 'special'
                elif ip_addr.is_link_local:
                    return 'special'
                elif ip_addr.version == 6 and ip_addr.is_site_local:  # Only for IPv6
                    return 'special'
                elif ip_addr.is_global:
                    return 'public'
                elif ip_addr.version == 6 and ip_addr.is_unspecified:  # Only for IPv6
                    return 'special'
                else:
                    return 'public'
            except ValueError:
                return 'public'
                
        def assign_layers(G, total_nodes, total_endpoints, total_layers, nodes_per_layer):
            ip_types = {'public': [], 'private': [], 'special': []}

            # Classify IPs for nodes starting from 15 onward (skip the first 15 nodes)
            for i in range(total_endpoints, total_nodes):
                ip = G.nodes[i]['ip']
                ip_type = classify_ip_type(ip)
                ip_types[ip_type].append(i)

            layer_dict = {}

            # Assign the first 15 nodes to layer 0
            for i in range(total_endpoints):
                layer_dict[i] = 0

            # Adjust nodes_per_layer to account for the first 15 nodes in layer 0
            nodes_per_layer[0] -= total_endpoints

            # Assign nodes to layers based on nodes_per_layer, starting from the highest layer
            for layer in range(total_layers - 1, 0, -1):  # Start from the highest layer (ignore layer 0)
                count = nodes_per_layer[layer]

                # Assign special IPs
                while count > 0 and ip_types['special']:
                    node = ip_types['special'].pop()
                    layer_dict[node] = layer
                    count -= 1

                # Assign private IPs
                while count > 0 and ip_types['private']:
                    node = ip_types['private'].pop()
                    layer_dict[node] = layer
                    count -= 1

                # Assign public IPs if still needed
                while count > 0 and ip_types['public']:
                    node = ip_types['public'].pop()
                    layer_dict[node] = layer
                    count -= 1

            # If there are any remaining nodes, distribute them starting from the lowest available layer
            remaining_nodes = ip_types['public'] + ip_types['private'] + ip_types['special']
            layer = 1  # Start from layer 1 since layer 0 is fixed
            while remaining_nodes:
                node = remaining_nodes.pop()
                while layer_dict.get(node):
                    layer = (layer + 1) % total_layers
                layer_dict[node] = layer

            # Ensure the first 15 nodes are in layer 0 and that all nodes have been assigned a layer
            assert all(layer_dict.get(i) == 0 for i in range(15)), "Not all first 15 nodes are in layer 0."
            assert len(layer_dict) == total_nodes, f"Not all nodes have been assigned a layer. Assigned: {len(layer_dict)}, Total: {total_nodes}"

            return layer_dict




        # Function to create edges with weights from edge_dict
        def create_edges(G, edge_dict, ip_mapping):
            for (src_ip, dst_ip), weight in edge_dict.items():
                if src_ip in ip_mapping and dst_ip in ip_mapping:
                    src_node = ip_mapping[src_ip]
                    dst_node = ip_mapping[dst_ip]
                    G.add_edge(src_node, dst_node, weight=weight)

        # Function to create subnets within layers
        def create_subnets(G, total_layers, subnet_nodes):
            for layer in range(total_layers):
                nodes_in_layer = [n for n, d in G.nodes(data=True) if d['layer'] == layer]
                layer_graph = nx.Graph(G.subgraph(nodes_in_layer))  # Create a modifiable copy of the subgraph

                subnets = subnet_nodes[layer]
                node_subnet_mapping = {}

                for subnet_index, subnet_size in enumerate(subnets):
                    current_subnet_nodes = []

                    while len(current_subnet_nodes) < subnet_size and layer_graph.nodes:
                        if layer_graph.edges:
                            # Find the edge with the highest weight
                            edge = max(layer_graph.edges(data=True), key=lambda x: x[2]['weight'])
                            # Select the node from the edge that is not already in the current subnet
                            node = edge[0] if edge[0] not in current_subnet_nodes else edge[1]
                        else:
                            # If no edges left, pick any node
                            node = random.choice(list(layer_graph.nodes))

                        current_subnet_nodes.append(node)
                        layer_graph.remove_node(node)
                        node_subnet_mapping[node] = subnet_index

                    for node in current_subnet_nodes:
                        G.nodes[node]['subnet'] = subnet_index


       # Function to create the network with the given edges
        def create_network(total_nodes, total_endpoints, total_layers, unique_ips, edge_dict):
            if total_endpoints >= total_nodes:
                raise ValueError("total_endpoints must be less than total_nodes")
            
            # Create a graph
            G = nx.Graph()

            # Ensure the first total_nodes are selected from the unique IPs
            node_ips = unique_ips[:total_nodes]
            node_mapping = {i: node_ips[i] for i in range(total_nodes)}
            ip_mapping = {v: k for k, v in node_mapping.items()}
            
            # Add nodes to the graph
            G.add_nodes_from(node_mapping.keys())
            
            # Set IP attribute for nodes
            nx.set_node_attributes(G, node_mapping, 'ip')

            subnets_per_layer.clear()
            subnet_nodes.clear()
            while len(subnets_per_layer) < total_layers:
                if len(subnets_per_layer) == 0: 
                    subnets_per_layer.append(1)
                l_subnets = random.randint(1, max_subnets_per_layer)
                if total_subnets - (sum(subnets_per_layer) + l_subnets) > total_layers - len(subnets_per_layer):
                    subnets_per_layer.append(l_subnets)

            while sum(subnets_per_layer) < total_subnets:
                s_index = random.randint(1, total_layers - 1)
                if subnets_per_layer[s_index] <= max_subnets_per_layer:
                    subnets_per_layer[s_index] = subnets_per_layer[s_index] + 1

            nodes_per_layer = [total_endpoints]
            for subs in subnets_per_layer[1:]:
                nodes_per_layer.append(min_nodes_per_subnet * subs)

            while sum(nodes_per_layer) < total_nodes:
                n_index = random.randint(1, total_layers - 1)
                nodes_per_layer[n_index] = nodes_per_layer[n_index] + 1

            for i, subnets in enumerate(subnets_per_layer):
                temp_subnet_nodes = [min_nodes_per_subnet for _i in range(subnets)]
                while sum(temp_subnet_nodes) < nodes_per_layer[i]:
                    n_index = random.randint(0, subnets - 1)
                    temp_subnet_nodes[n_index] = temp_subnet_nodes[n_index] + 1
                subnet_nodes.append(temp_subnet_nodes)

            # Assign layers to nodes
            layer_dict = assign_layers(G, total_nodes, total_endpoints, total_layers, nodes_per_layer)
            nx.set_node_attributes(G, layer_dict, 'layer')

            # Create edges with weights from edge_dict
            create_edges(G, edge_dict, ip_mapping)
            create_subnets(G, total_layers, subnet_nodes)

            return G

        def layered_layout(G, total_layers, subnet_nodes, subnets_per_layer):
            pos = {}
            min_y_pos = 0
            max_y_pos = 10
            x_gap_between_layers = 6  # Horizontal gap between layers
            subnet_gap_factor = 0.2  # Factor to pull nodes in the same subnet closer

            # Position layer 0 (endpoints) linearly along the y-axis
            total_endpoints = len([n for n, d in G.nodes(data=True) if d['layer'] == 0])
            for n in range(total_endpoints):
                position = (n + 1) / total_endpoints * (max_y_pos - min_y_pos) + min_y_pos
                pos[n] = np.array([0, position])

            # Position nodes in other layers
            for i in range(1, total_layers):
                layer_nodes = [n for n, d in G.nodes(data=True) if d['layer'] == i]
                layer_subnets = sorted(set(G.nodes[n]['subnet'] for n in layer_nodes))

                for j, subnet in enumerate(layer_subnets):
                    subnet_nodes = [n for n in layer_nodes if G.nodes[n]['subnet'] == subnet]
                    if len(subnet_nodes) > 1:
                        subgraph_pos = nx.spring_layout(nx.complete_graph(len(subnet_nodes)), scale=subnet_gap_factor)
                    else:
                        subgraph_pos = {0: (0, 0)}  # Single node subnet

                    # Calculate vertical positioning for subnets within a layer
                    num_subnets = len(layer_subnets)
                    if num_subnets > 1:
                        vertical_positions = np.linspace(min_y_pos, max_y_pos, num_subnets + 1)
                        y_min = vertical_positions[j]
                        y_max = vertical_positions[j + 1]
                    else:
                        y_min = min_y_pos
                        y_max = max_y_pos

                    y_center = (y_min + y_max) / 2
                    x_center = i * x_gap_between_layers

                    for k, node in enumerate(subnet_nodes):
                        v = subgraph_pos[k]
                        y = v[1] * (y_max - y_min) / 2 + y_center  # Spread out nodes vertically within the subnet
                        x = v[0] * x_gap_between_layers / 2 + x_center  # Spread out nodes horizontally within the layer :)
                        pos[node] = np.array([x, y])

            return pos

        def sample_node_edge(total_nodes, total_endpoints, total_layers):
            # Select the dataset "NF-CSE-CIC-IDS2018" - 3 other options, to play around later.
            # Data already cleaned, removed attacker IPs. 
            loaded_network_data = np.load('../mtdnetwork/data/Edge_iiot.npy', allow_pickle=True).item()    
            dataset = loaded_network_data["EdgeIIOT"]
            unique_ips = dataset['node_list']
            edge_dict = dataset['edge_list']
            attackers = dataset['attackers']
            tempIP = []
            for ip in unique_ips:
                if ip in attackers:
                    continue
                tempIP.append(ip) 

            # Sample IPs - Add endpoints and special ips (highest layers)
            sample = []
            sample.extend(attackers[:total_endpoints])
            sample.extend(tempIP)
            
            # Filter edge list
            filtered_edge_list = edge_dict
            
            return sample, filtered_edge_list

        # Parameters
        total_nodes = self.total_nodes
        total_endpoints = self.total_endpoints
        total_layers = self.layers
        total_subnets = self.total_subnets


        subnets_per_layer = []
        subnet_nodes = []

        unique_ips, edge_dict = sample_node_edge(total_nodes, total_endpoints, total_layers)
        # Create the network
        self.graph = nx.Graph()
        self.graph = create_network(total_nodes, total_endpoints, total_layers, unique_ips, edge_dict)

        # Generate the custom layout
        self.pos = layered_layout(self.graph, total_layers, subnet_nodes, subnets_per_layer)
                
        def check_traversability(G, start_nodes):
            seen = set()
            for start_node in start_nodes:
                # Perform BFS or DFS from the start node
                for node in nx.dfs_preorder_nodes(G, start_node):
                    seen.add(node)
            return seen

        start_nodes = list(range(15))
        traversable_nodes = check_traversability(self.graph, start_nodes)

        # List of colors for the layers (modify as needed)
        layer_colors = ['blue', 'green', 'yellow', 'purple']

        # Create a color map for nodes based on traversal
        node_colors = []
        for node in self.graph.nodes:
            if node not in traversable_nodes:
                # Disconnected nodes
                node_colors.append('red')
            else:
                # Assign color based on layer
                layer = self.graph.nodes[node]['layer']
                node_colors.append(layer_colors[layer % len(layer_colors)])

        # Visualize the network with the custom layout
        self.colour_map = []
        for node in self.graph.nodes:
            layer = self.graph.nodes[node]['layer']
            color = constants.NODE_COLOURS[layer]
            self.colour_map.append(color)

        # Update self.colour_map for nodes that are red in node_colors
        for i, color in enumerate(node_colors):
            if color == 'red':
                self.colour_map[i] = 'red'

            

        # Updates Colour of target node to red
        if self.network_type == 0:
            self.colour_map[self.target_node] = "red"
        
        self.setup_network()





############################################################################################################

    def get_total_endpoints(self):
        return self.total_endpoints

    def get_exposed_endpoints(self):
        return self.exposed_endpoints

    def get_database(self):
        return self._database

    def get_total_database(self):
        return self.total_database

    def get_scorer(self):
        return self.scorer

    def get_statistics(self):
        return self.scorer.get_statistics()

    def get_service_generator(self):
        return self.service_generator

    def get_hosts(self):
        return dict(nx.get_node_attributes(self.graph, "host"))

    def get_subnets(self):
        return dict(nx.get_node_attributes(self.graph, "subnet"))

    def get_layers(self):
        return dict(nx.get_node_attributes(self.graph, "layer"))

    def get_graph(self):
        return self.graph

    def get_graph_copy(self):
        return self.graph.copy()

    def get_pos(self):
        return self.pos

    def get_colourmap(self):
        return self.colour_map

    def get_total_nodes(self):
        return self.total_nodes

    def get_network_type(self):
        return self.network_type

    def get_unique_subnets(self):
        subnets = self.get_subnets()
        layers = self.get_layers()

        layer_subnets = {}

        for host_id, subnet_id in subnets.items():
            layer_id = layers[host_id]

            if not layer_id in layer_subnets:
                layer_subnets[layer_id] = {}

            layer_subnets[layer_id][subnet_id] = layer_subnets[layer_id].get(subnet_id, []) + [host_id]

        return layer_subnets

    def get_reachable(self):
        """
        Returns:
            The reachable array
        """
        return self.reachable

    def get_node_per_layer(self):
        """
        Returns:
            Number of nodes per layer
        """
        return self.node_per_layer

    def get_users_list(self):
        return self.users_list

    def get_users_per_host(self):
        return self.users_per_host

    def get_target_node(self):
        return self.target_node
    
    def add_shortest_path(self):
        """
            Shortest Attack Path Variability (SAPV): changes on shortest attack paths over time
        """
        shortest_path = self.get_path_from_exposed(self.target_node, self.graph)[0]
       
        self.scorer.add_shortest_path(shortest_path)

    def add_attack_path_exposure(self):
        """
        Adds the Attack Path Exposure Score to statistics
        """
        self.scorer.add_attack_path_exposure(self.attack_path_exposure())

    def attack_path_exposure(self):
        """
        Gets the total attack path exposure, scoring each node based on the % of new vulnerabilities found in each node on the shortest path to the target_node out of 1

        Returns:
            ave_score: Score of each host added up, divided by the number of hosts
        """
        shortest_path = self.get_path_from_exposed(self.target_node, self.graph)[0]
        vuln_list = []
        total_score = 0
        for host_id in shortest_path:
            host = self.get_host(host_id)
            service_id_list = host.get_path_from_exposed()
            services = host.get_services_from_list(service_id_list)
            not_unique_host_vulns = 0
            total_host_vulns = 0

            for service in services:
                vulns = service.get_vulns()
                total_host_vulns = len(vulns) + total_host_vulns

                for vuln in vulns:
                    if vuln not in vuln_list:
                        vuln_list.append(vuln)
                    else:
                        not_unique_host_vulns = not_unique_host_vulns + 1
            if total_host_vulns - not_unique_host_vulns == 0:
                new_vuln_percent = 0
            else:
                new_vuln_percent = (total_host_vulns - not_unique_host_vulns) / total_host_vulns
            total_score = total_score + new_vuln_percent
        if len(shortest_path) > 0:
            return total_score / len(shortest_path)
        else:
            return total_score

    def setup_users(self, user_to_nodes_ratio, prob_user_reuse_pass, users_per_host):
        """
        Randomly generates users that use the network

        Parameters:
            user_to_nodes_ratio:
                the percent of users in comparison to host machines.
                each node will then be given `int(1/user_to_nodes_ratio)` users each (less users more users on each computer).
            prob_user_reuse_pass:
                the probability that a user has reused their password.
            users_per_host:
                how many users are allocated to each host on the network.
        """
        self.total_users = int(self.total_nodes * user_to_nodes_ratio)
        if self.total_users < 1:
            self.total_users = 1

        names = [x.decode() for x in pkg_resources.resource_string('mtdnetwork', "data/first-names.txt").splitlines()]

        random_users = random.choices(names, k=self.total_users)
        self.users_list = [
            (user, random.random() < prob_user_reuse_pass)
            for user in random_users
        ]

        self.users_per_host = users_per_host

    def update_reachable_mtd(self):
        """
        Updates the Reachable array with only compromised nodes that are reachable after MTD
        NOTE: Probably can be optimised for speed
        """
        self.reachable = self.exposed_endpoints.copy()
        compromised_neighbour_nodes = []

        # Appends all neighbouring hosts from endpoints
        for endpoint in self.exposed_endpoints:
            visible_hosts = list(self.graph.neighbors(endpoint))
            for host in visible_hosts:
                for c_host in self.compromised_hosts:
                    if host == c_host:
                        compromised_neighbour_nodes.append(host)
                        self.reachable.append(host)

        # Checks if neighbouring hosts of compromised node are also compromised, if so add them to the list
        while len(compromised_neighbour_nodes) != 0:
            appended_host = compromised_neighbour_nodes.pop(0)
            visible_hosts = list(self.graph.neighbors(appended_host))
            for host in visible_hosts:
                for c_host in self.compromised_hosts:
                    if host == c_host:
                        if host not in self.reachable:
                            compromised_neighbour_nodes.append(host)
                            self.reachable.append(host)
                        # repeated = False
                        # for reachable in self.reachable:
                        #     if reachable == host:
                        #         repeated = True
                        # if repeated == False:
                        #     compromised_neighbour_nodes.append(host)
                        #     self.reachable.append(host)

    def update_reachable_compromise(self, compromised_node_id, compromised_hosts):
        """
        Updates the Reachable with the node_id of the compromised node
        """
        self.reachable.append(compromised_node_id)
        appended_host = compromised_node_id
        self.compromised_hosts = compromised_hosts
        all_reachable_hosts_added = False
        compromised_neighbour_nodes = []

        # Checks if neighbouring hosts of compromised node are also compromised, if so add them to the list
        while all_reachable_hosts_added == False:
            visible_hosts = list(self.graph.neighbors(appended_host))
            for host in visible_hosts:
                for c_host in compromised_hosts:
                    if host == c_host:
                        # repeated = False
                        # for reachable in self.reachable:
                        #     if reachable == host:
                        #         repeated = True
                        # if repeated == False:
                        if host not in self.reachable:
                            compromised_neighbour_nodes.append(host)
                            self.reachable.append(host)

            if len(compromised_neighbour_nodes) == 0:
                all_reachable_hosts_added = True
            else:
                appended_host = compromised_neighbour_nodes.pop(0)

    def get_host_id_priority(self, host_id):
        """
        Assign priority of host_id based on layer

        Parameters:
            host_id: node id of the desired node

        Returns:
            Priority: An integer based on tag_priority array, with target node scoring 0, top priority node scoring 1, and subsequent nodes scoring 1 higher
        """
        if host_id == self.target_node:
            return 0
        layers = self.get_layers()
        host_layer = layers.get(host_id)
        priority = -1
        i = 0
        for tag in self.tag_priority:
            if self.tags[host_layer] == tag:
                priority = i
            i += 1
        return priority + 1

    def assign_tags(self):
        """
        Assigns the tags to layers from constants.py
        """
        i = 0
        while i < self.layers:
            self.tags.append(constants.HOST_TAGS[i])
            i += 1

    def assign_tag_priority(self):
        """
        Orders tags based on priority
        """
        i = 0
        order = []
        while i < self.layers:
            dist = abs(self.target_layer - i)
            order.append(dist)
            i += 1

        layer_index = 0
        priority = 0
        order_index = 0
        while layer_index < self.layers:
            for order_prio in order:
                if order_prio == priority:
                    self.tag_priority.append(self.tags[order_index])
                    layer_index += 1
                order_index += 1
            priority += 1
            order_index = 0

    def get_path_from_exposed(self, target_node, graph=None):
        """
        Gets the shortest path and distance from the exposed endpoints.

        Can also specify a subgraph to use for finding

        Parameters:
            target_node:
                the target node to reach to

        Returns:
            a tuple where the first element is the shortest path and the second element is the distance
        """
        if graph is None:
            graph = self.graph

        shortest_distance = constants.LARGE_INT
        shortest_path = []

        for ex_node in self.exposed_endpoints:
            try:
                path = nx.shortest_path(graph, ex_node, target_node)
                path_len = len(path)

                if path_len < shortest_distance:
                    shortest_distance = path_len
                    shortest_path = path
            except:
                pass

        # This function is used when the attacker can't find a path to host

        # if shortest_distance == constants.LARGE_INT:
        #     raise exceptions.ActionBlockedError

        return shortest_path, shortest_distance

    def get_shortest_distance_from_exposed_or_pivot(self, host_id, pivot_host_id=-1, graph=None):
        if host_id in self.exposed_endpoints:
            return 0
        if graph is None:
            graph = self.graph
        shortest_distance = self.get_path_from_exposed(host_id, graph=graph)[1]
        if pivot_host_id >= 0:
            try:
                path = nx.shortest_path(graph, host_id, pivot_host_id)
                path_len = len(path)

                if path_len < shortest_distance:
                    shortest_distance = path_len
            except:
                pass

        return shortest_distance

    def sort_by_distance_from_exposed_and_pivot_host(self, host_stack, compromised_hosts, pivot_host_id=-1):
        """
        Sorts the Host Stack by the shortest number of hops to reach the target hosts.

        Parameters:
            host_stack:
                a list of host IDs the attacker wants to attack
            compromised_hosts:
                a list of host IDs the hacker has compromised
            pivot_host_id:
                the ID of the host that is compromised that the hacker is using to pivot from.
                if None then it only sorts by the exposed endpoints
        """

        visible_network = self.get_hacker_visible_graph()

        non_exposed_endpoints = [
            host_id
            for host_id in host_stack
            if not host_id in self.exposed_endpoints
        ]

        return sorted(
            non_exposed_endpoints,
            key=lambda host_id: self.get_shortest_distance_from_exposed_or_pivot(
                host_id,
                pivot_host_id=pivot_host_id,
                graph=visible_network
            ) + random.random()
        ) + [
                   host_id
                   for host_id in self.exposed_endpoints
                   if host_id in host_stack
               ]

    def get_neighbors(self, host_id):
        """
        Returns the neighbours for a host.

        Parameters:
            host_id:
                the host ID to get the neighbors from

        Returns:
            a list of the neighbors for the host.
        """
        return list(self.graph.neighbors(host_id))

    def setup_network(self):
        """
        Using the generated graph, generates a host for each node on the graph.
        """
        
        for host_id in self.nodes:
            node_os = Host.get_random_os()
            node_os_version = Host.get_random_os_version(node_os)
            node_ip = self.graph.nodes[host_id]['ip']
            self.graph.nodes[host_id]["host"] = Host(
                node_os,
                node_os_version,
                host_id,
                node_ip,
                random.choices(self.users_list, k=self.users_per_host),
                self,
                self.service_generator
            )
         # Remove the 'ip' attribute from each node
        for node_id in self.graph.nodes:
            if 'ip' in self.graph.nodes[node_id]:
                del self.graph.nodes[node_id]['ip']
        

    def get_hacker_visible_graph(self):
        """
        Returns the Network graph that is visible to the hacker depending on the hosts that have already been compromised

        """
        visible_hosts = []
        for c_host in self.reachable:
            visible_hosts = visible_hosts + list(self.graph.neighbors(c_host))

        visible_hosts = visible_hosts + self.reachable
        visible_hosts = visible_hosts + self.exposed_endpoints

        return self.graph.subgraph(
            list(set(visible_hosts))
        )

    def get_host(self, host_id):
        """
        Gets the Host instance based on the host_id

        Parameters:
            the ID of the Host Instance

        Returns:
            the corresponding Host instance
        """

        return self.graph.nodes.get(host_id, {}).get("host", None)

    def get_total_vulns(self):
        return self.total_vulns

    def get_vuln_dict(self):
        """
        Gets all the vulnerabilities for every hosts and puts them in vuln_dict

        Returns:
            the freuqency of every vuln
        """
        for host_id in self.nodes:
            host = self.get_host(host_id)
            vulns = host.get_all_vulns()
            self.total_vulns += len(vulns)
            self.vuln_dict[host_id] = vulns
            for v in vulns:
                v_id = v.get_id()
                if v_id in self.vuln_count:
                    self.vuln_count[v.get_id()] += 1
                else:
                    self.vuln_count[v.get_id()] = 1
        return self.vuln_count

    def get_total_services(self):
        return self.total_services

    def get_service_dict(self):
        """
        Gets all the services for every hosts and puts them in service_dict

        Returns:
            the freuqency of every service
        """
        for host_id in self.nodes:
            host = self.get_host(host_id)
            services = host.get_all_services()
            self.total_services += len(services)
            self.service_dict[host_id] = services
            for s in services:
                s_id = s.get_id()
                if s_id in self.service_count:
                    self.service_count[s.get_id()] += 1
                else:
                    self.service_count[s.get_id()] = 1
        return self.service_count

    def is_target_compromised(self, target_node):
        if self.get_host(target_node).is_compromised():
            return True
        else:
            return False
        
    def set_target_node(self, node_id):
        self.target_node = node_id
    
    def get_target_node(self):
        return self.target_node
    

    def is_compromised(self, compromised_hosts):
        """
        Checks if the Network has been completely compromised.

        Parameters:
            compromised_hosts:
                the list of host IDs that have been compromised by the hacker

        Returns:
            boolean
        """
        return len(compromised_hosts) == self.total_nodes

    def draw(self):
        plt.figure(1, figsize=(15, 12))
        nx.draw(self.graph, pos=self.pos, with_labels=True, node_size=500, node_color=self.colour_map, font_size=8, font_color="white", font_weight="bold")
        plt.show()
        directory = os.getcwd()
        plt.savefig(directory + '/experimental_data/plots/network.png')