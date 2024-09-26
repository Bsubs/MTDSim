import simpy
import logging
import random
from mtdnetwork.component.time_generator import exponential_variates
from mtdnetwork.data.constants import ATTACK_DURATION
import networkx as nx


class AttackOperation:
    def __init__(self, env, end_event, adversary, proceed_time=0):
        """

        :param env: the parameter to facilitate simPY env framework
        :param adversary: the simulation attacker
        :param proceed_time: the time to proceed attack simulation
        """

        self.env = env
        self.end_event = end_event
        self.adversary = adversary
        self._attack_process = None
        self._interrupted_mtd = None
        self._proceed_time = proceed_time
        self.count = 0

        # New variables for attack dictionary processing
        self.currentAttack = None
        self.attackList = [attack['DST_IP'] for attack in self.adversary.attackDictionary]
        self.currAttackIndex = 0
        self.targetIp = None
        self.targetNode = None
        self.interruptedAttackForRecycling = []
        self.logging = False


    def proceed_attack(self):
        if self.currentAttack is None:
            # Initialize the first attack
            if self.currAttackIndex < len(self.attackList):
                self.targetIp = self.attackList[self.currAttackIndex]
                self.set_target_node()

                # Check if the target node is already compromised
                if self.targetIp in self.adversary.compromisedIps:
                    if self.logging:
                        logging.info(f"Target IP {self.targetIp} is already compromised. Skipping to the next attack.")
                    self.move_to_next_attack()
                    return

                self.currentAttack = self.targetIp  # Mark as the current attack
            else:
                # All attacks have been processed
                logging.info("All attacks in the attack dictionary have been completed.")
                self.end_event.succeed()
                return

        if self.adversary.get_curr_process() == 'SCAN_HOST':
            self._scan_host()
        elif self.adversary.get_curr_process() == 'ENUM_HOST':
            self._enum_host()
        elif self.adversary.get_curr_process() == 'SCAN_PORT':
            self._scan_port()
        elif self.adversary.get_curr_process() == 'SCAN_NEIGHBOR':
            self._scan_neighbors()
        elif self.adversary.get_curr_process() == 'EXPLOIT_VULN':
            self._exploit_vuln()
        elif self.adversary.get_curr_process() == 'BRUTE_FORCE':
            self._brute_force()

    def set_target_node(self):
        network = self.adversary.network
        for host_id, host in network.get_hosts().items():
            if host.get_ip() == self.targetIp:
                self.targetNode = host_id
                if self.logging:
                    logging.info(f"Target IP {self.targetIp} found as host ID {self.targetNode}.")
                    logging.info(f"Neighbours of Target Ip are:{network.get_neighbors(self.targetNode)}")
                return
        logging.warning(f"Target IP {self.targetIp} not found in the network. Ending attack sequence.")
        self.end_event.succeed()

    def move_to_next_attack(self):
        self.currAttackIndex += 1
        self.currentAttack = None
        if self.logging:
            logging.info(f"Attack Path exposure: {self.adversary.network.attack_path_exposure()}")
        if self.currAttackIndex < len(self.attackList):

            self.targetIp = self.attackList[self.currAttackIndex]
            self.set_target_node()

            if self.targetIp in self.adversary.compromisedIps:
                if self.logging:
                    logging.info(f"Target IP {self.targetIp} is already compromised. Checking Reachability status")
                self._check_reachable()
                return

            self.adversary.set_curr_host_id(-1)
            self.adversary.set_curr_host(None)
            if self.logging:
                logging.info('Adversary: Restarting with SCAN_HOST.')
            self._scan_host()
        else:
            if self.adversary.recycle_attacks == True:
                if self.logging:
                    logging.info("Attack List completed, Adding Unsuccessful Attacks if any")
                if len(self.interruptedAttackForRecycling) != 0:
                    if self.logging:
                        logging.info(f"Added Attacks to Attack List: {self.interruptedAttackForRecycling} ")
                    self.attackList.extend(self.interruptedAttackForRecycling)
                    self.interruptedAttackForRecycling = []
                    self.currAttackIndex -= 1
                    self.move_to_next_attack()
                    return
            if self.logging:
                logging.info("All attacks in the attack dictionary have been completed.")
                logging.info(f"Current Incomplete attacks: {self.interruptedAttackForRecycling}")
                logging.info(f"Successful Attacks: {self.adversary.successfulAttack}")
                logging.info(f"Unsuccessful Attacks: {self.adversary.interruptedAttacks}")
            self.end_event.succeed()


    def _execute_attack_action(self, time, attack_action):
        """
        a function to execute a given time-consuming attack action
        :param time: The time duration before executing an attack action.
        :param attack_action: attack action
        """
        start_time = self.env.now + self._proceed_time
        try:
            if self.logging:
                logging.info("Adversary: Start %s at %.1fs." % (self.adversary.get_curr_process(), start_time))
            # Stop for the attack duration ie time
            yield self.env.timeout(time)
        # Execute attacks unless mtd raises an interrupt. then handle it (Stopped an attack)
        except simpy.Interrupt:
            self.env.process(self._handle_interrupt(start_time, self.adversary.get_curr_process()))
            return

        # attack processed ready to attack now 
        finish_time = self.env.now + self._proceed_time
        if self.logging:
            logging.info("Adversary: Processed %s at %.1fs." % (self.adversary.get_curr_process(), finish_time))
        self.adversary.get_attack_stats().append_attack_operation_record(self.adversary.get_curr_process(), start_time,
                                                                         finish_time, self.adversary)
        # So the duration actually exists as a timeout for processing, the last thing we do is run the attack, which takes its own time. 
        attack_action()

    def _scan_host(self):
        """
        raise an SCAN_HOST action
        """
        self.adversary.set_curr_process('SCAN_HOST')
        self._attack_process = self.env.process(self._execute_attack_action(ATTACK_DURATION['SCAN_HOST'],
                                                                            self._execute_scan_host))

    def _enum_host(self):
        """
        raise an ENUM_HOST action
        """
        # Another check over here which is redundant..
        if len(self.adversary.get_host_stack()) > 0:
            self.adversary.set_curr_process('ENUM_HOST')
            self._attack_process = self.env.process(self._execute_attack_action(ATTACK_DURATION['ENUM_HOST'],
                                                                                self._execute_enum_host))
        # But this one makes sense, scan host isnt in scan host function, so this works here if no hosts found 
        else:
            self._scan_host()

    def _scan_port(self):
        """
        raise an SCAN_PORT action
        """
        self.adversary.set_curr_process('SCAN_PORT')
        self._attack_process = self.env.process(self._execute_attack_action(ATTACK_DURATION['SCAN_PORT'],
                                                                            self._execute_scan_port))

    def _exploit_vuln(self):
        """
        raise an EXPLOIT_VULN action
        """
        # exploit_time = exponential_variates(ATTACK_DURATION['EXPLOIT_VULN'][0], ATTACK_DURATION['EXPLOIT_VULN'][1])
        adversary = self.adversary
        # Gets all current vulnerabilities for this current host. Get vulns from the current ports. 
        adversary.set_curr_vulns(adversary.get_curr_host().get_vulns(adversary.get_curr_ports()))
        self.adversary.set_curr_process('EXPLOIT_VULN')
        self._attack_process = self.env.process(self._execute_exploit_vuln(adversary.get_curr_vulns()))

    def _brute_force(self):
        """
        raise an BRUTE_FORCE action
        """
        self.adversary.set_curr_process('BRUTE_FORCE')
        self._attack_process = self.env.process(self._execute_attack_action(ATTACK_DURATION['BRUTE_FORCE'],
                                                                            self._execute_brute_force))

    def _scan_neighbors(self):
        """
        raise an SCAN_NEIGHBOR action
        """
        self.adversary.set_curr_process('SCAN_NEIGHBOR')
        self._attack_process = self.env.process(self._execute_attack_action(ATTACK_DURATION['SCAN_NEIGHBOR'],
                                                                            self._execute_scan_neighbors))

    def _check_reachable(self):
        """
        raise a Check_Reachable action
        """
        self.adversary.set_curr_process('CHECK_REACHABLE')
        self._attack_process = self.env.process(self._execute_attack_action(ATTACK_DURATION['CHECK_REACHABLE'],
                                                                            self._execute_check_reachable))
        
    def _handle_interrupt(self, start_time, name):
        """
        a function to handle the interrupt of the attack action caused by MTD operations
        :param start_time: the start time of the attack action
        :param name: the name of the attack action
        """
        adversary = self.adversary
        current_attack = {
        "process": adversary.get_curr_process(),
        "host_id": adversary.get_curr_host_id(),
        "host_ip": adversary.get_curr_host().get_ip() if adversary.get_curr_host() else None,
        "start_time": start_time,
        "interrupted_time": self.env.now,
        }
        adversary.get_attack_stats().append_attack_operation_record(name, start_time,
                                                                    self.env.now + self._proceed_time,
                                                                    adversary, self._interrupted_mtd)
        
        self.adversary.interruptedAttacks.append(current_attack)
        self.interruptedAttackForRecycling.append(self.targetIp)
        self.adversary.unsuccessfulCount += 1
        if self.logging:
            logging.info(f"Attack {current_attack} thwarted by MTD at {self.env.now + self._proceed_time}s")
        # confusion penalty caused by MTD operation
        yield self.env.timeout(exponential_variates(ATTACK_DURATION['PENALTY'], 0.5))
        # If network based mtd then i need to start again and scan host etc
        if self._interrupted_mtd.get_resource_type() == 'network':
            self._interrupted_mtd = None
            # Validate compromised list after MTD
            # self.validate_compromised_list_after_mtd()
            # Move on to the next attack
            if self.logging:
                logging.info('Adversary: Moving to the next attack after network MTD.')
            self.move_to_next_attack()
            
        # If not network based ie service diversity or something, applicaiton based oS diversity then i can just carry on but restart with scanning ports again
        elif self._interrupted_mtd.get_resource_type() == 'application':
            self._interrupted_mtd = None
            if self.logging:
                logging.info('Adversary: Restarting with SCAN_PORT at %.1fs!' % (self.env.now + self._proceed_time))
            self._scan_port()
            
    def validate_compromised_list_after_mtd(self):
        """
        Validate and update the compromised hosts and IPs list after an MTD operation.
        Handles both IP shuffles and complete topology shuffles.
        """
        network = self.adversary.get_network()
        new_compromised_ips = []
        new_compromised_hosts = []

        # Iterate through all hosts in the network to update their status after IP Shuffle
        for host_id, host in network.get_hosts().items():
            current_ip = host.get_ip()

            # If the host is compromised in the new network, update its status
            if host.is_compromised():
                new_compromised_hosts.append(host_id)
                if current_ip not in new_compromised_ips:
                    new_compromised_ips.append(current_ip)

        # Update the adversary's list of compromised hosts and IPs
        self.adversary.set_compromised_hosts(new_compromised_hosts)
        self.adversary.compromisedIps = new_compromised_ips
        
        if self.logging:
            logging.info(f"Updated Compromised Hosts after MTD: {new_compromised_hosts}")
            logging.info(f"Updated Compromised IPs after MTD: {new_compromised_ips}")


    def _execute_scan_host(self):
        """
        Starts the Network enumeration stage.
        Sets up the order of hosts that the hacker will attempt to compromise
        The order is sorted by distance from the exposed endpoints which is done
        in the function adversary.network.host_scan().
        If the scan returns nothing from the scan, then the attacker will stop
        """
        # logging.info("Scan Host initialised")
        adversary = self.adversary
        compromised_hosts = adversary.get_compromised_hosts()
        # logging.info(f"Current Compromised Hosts: {compromised_hosts}")
        stop_attack = adversary.get_stop_attack()
        network = adversary.get_network()

        adversary.set_pivot_host_id(-1)
        visible_network = network.get_hacker_visible_graph()

        # scan_time = constants.NETWORK_HOST_DISCOVER_TIME * visible_network.number_of_nodes()
        
        uncompromised_hosts = []
        for c_host in compromised_hosts:
            neighbors = list(network.graph.neighbors(c_host))
            # logging.info(f"Neighbors of {c_host}: {neighbors}")
            
            for neighbor in neighbors:
                if neighbor not in compromised_hosts and neighbor not in network.exposed_endpoints:
                    path, _ = network.get_path_from_exposed(neighbor, graph=visible_network)
                    if len(path) > 0:
                        uncompromised_hosts.append(neighbor)
                        # logging.info(f"Adding host {neighbor} to uncompromised hosts list.")
                        
        # logging.info("Uncompromised Hosts after the adding them to reachable Loop: ")
        # logging.info(uncompromised_hosts)

        # Add random element from 0 to 1 so the scan does not return the same order of hosts each time for the hacker
        uncompromised_hosts = sorted(
            uncompromised_hosts,
            key=lambda host_id: network.get_path_from_exposed(host_id, graph=visible_network)[1] + random.random()
        )
        # logging.info(f"Uncompromised Hosts after loop: {uncompromised_hosts}")

        uncompromised_hosts = uncompromised_hosts + [
            ex_node
            for ex_node in network.exposed_endpoints
            if ex_node not in compromised_hosts
        ]
        # logging.info(f"Uncompromised Hosts after sorting: {uncompromised_hosts}")
        discovered_hosts = [n for n in uncompromised_hosts if n not in stop_attack]
        # logging.info(f"Discovered Hosts: {discovered_hosts}")

        # logging.info("DISCOVERED HOSTS from Uncompromised Hosts!: ")
        # logging.info(discovered_hosts)

        adversary.set_host_stack(discovered_hosts)
        if len(adversary.get_host_stack()) > 0:
            # logging.info("Enuming hosts because host stack is greater than 0 ")
            self._enum_host()
        else:
            # terminate the whole process
            if self.logging:
                logging.info("Adversary: Cannot discover new hosts!")
            self._check_reachable()
            return

    def _execute_enum_host(self):
        """
        Starts enumerating each host by popping off the host id from the top of the host stack
        time for host hopping required
        Checks if the Hacker has already compromised and backdoored the target host
        """
        # logging.info("ENUM FIRST LINE")
        adversary = self.adversary
        network = adversary.get_network()
        # logging.info("Current host stack after scanning: ")
        # logging.info(adversary.get_host_stack())
        adversary.set_host_stack(network.sort_by_distance_from_exposed_and_pivot_host(
            adversary.get_host_stack(),
            adversary.get_compromised_hosts(),
            pivot_host_id=adversary.get_pivot_host_id()
        ))
        # logging.info("Current host stack after organising the stack by distance from exposed and pivot hosts: ")
        # logging.info(adversary.get_host_stack())
        adversary.set_curr_host_id(adversary.get_host_stack().pop(0))
        # Popped off the first host from the list ie organised best hop so its best jump
        adversary.set_curr_host(network.get_host(adversary.get_curr_host_id()))
        
         # Check if the current host is already compromised and matches the target IP
        current_ip = adversary.get_curr_host().get_ip()
        if current_ip in self.adversary.compromisedIps and current_ip == self.targetIp:
            if self.logging:
                logging.info(f"Current host IP {current_ip} is already compromised and is the target IP.")
                logging.info(f"Target node {self.targetNode} has been reached. Marking attack as successful.")
            self.add_successful_attack()
            self.move_to_next_attack()
            return
        
        # Sets node as unattackable if has been attack too many times
        adversary.get_attack_counter()[adversary.get_curr_host_id()] += 1
        # Attack counter is a list where the index of the list represents each curr host ID, and the value is the number of attacks
        if adversary.get_attack_counter()[
            adversary.get_curr_host_id()] == adversary.get_attack_threshold():
            # target node feature
            if adversary.get_curr_host_id() != network.get_target_node() and network.network_type == 0:
                # Get stop attack is a list, which has all the host ids of nodes to not attack. 
                adversary.get_stop_attack().append(adversary.get_curr_host_id())
        # Checks if max attack attempts has been reached, empty stacks if reached
        # if adversary.get_curr_attempts() >= adversary.get_max_attack_attempts():
        #     adversary.set_host_stack([])
        #     return

        # Reset the cur ports and curr vulns
        adversary.set_curr_ports([])
        adversary.set_curr_vulns([])

        # Sets the next host that the Hacker will pivot from to compromise other hosts
        # The pivot host needs to be a compromised host that the hacker can access
        self._set_next_pivot_host()
        if adversary.get_curr_host().compromised:
            self.update_compromise_progress(self.env.now, self._proceed_time, self._enum_host)
            # self._enum_host()
        #not compromised
        else:
            # Attack event triggered
            # logging.info("Else not compromised ENUM")
            self._scan_port()

    def _execute_scan_port(self):
        """
        Starts a port scan on the target host
        Checks if a compromised user has reused their credentials on the target host
        Phase 1
        """
        adversary = self.adversary
        
        if adversary.get_curr_host() == None:
            self.adversary.set_curr_host_id(-1)
            self.adversary.set_curr_host(None)
            if self.logging:
                logging.info('Adversary: No Host Set in Port Scan -- Restarting with SCAN_HOST.')
            self._scan_host()
            return
        
        # Port scan begins, and sets the current ports to this. 
        adversary.set_curr_ports(adversary.get_curr_host().port_scan())
        user_reuse = adversary.get_curr_host().can_auto_compromise_with_users(
            adversary.get_compromised_users())
        if user_reuse:
            #Given that there is a userwhose password has been reused, then assume this host is compromised. We can start scanning neighbours again
            self.update_compromise_progress(self.env.now, self._proceed_time, self._scan_neighbors)
            # self._scan_neighbors()
            return
        #No User reused, and then start exploiting vulnerabilities. 
        self._exploit_vuln()

    def _execute_exploit_vuln(self, vulns):
        """
        Finds the top 5 vulnerabilities based on RoA score and have not been exploited yet that the
        Tries exploiting the vulnerabilities to compromise the host
        Checks if the adversary was able to successfully compromise the host
        Phase 2
        """
        adversary = self.adversary
        for vuln in vulns:
            exploit_time = exponential_variates(vuln.exploit_time(host=adversary.get_curr_host()), 0.5)
            start_time = self.env.now + self._proceed_time
            try:
                # All logging happens inside this function. 
                if self.logging:
                    logging.info(
                    "Adversary: Start %s %s on host %s at %.1fs." % (self.adversary.get_curr_process(), vuln.id,
                                                                     self.adversary.get_curr_host_id(), start_time))
                yield self.env.timeout(exploit_time)
            except simpy.Interrupt:
                self.env.process(self._handle_interrupt(start_time, self.adversary.get_curr_process()))
                return
            finish_time = self.env.now + self._proceed_time
            if self.logging:
                logging.info(
                "Adversary: Processed %s %s on host %s at %.1fs." % (self.adversary.get_curr_process(), vuln.id,
                                                                     self.adversary.get_curr_host_id(), finish_time))
            self.adversary.get_attack_stats().append_attack_operation_record(self.adversary.get_curr_process(),
                                                                             start_time,
                                                                             finish_time, self.adversary)
            vuln.network(host=adversary.get_curr_host())
            # cumulative vulnerability exploitation attempts
            adversary.set_curr_attempts(adversary.get_curr_attempts() + 1)
        if adversary.get_curr_host().check_compromised():
            for vuln in adversary.get_curr_vulns():
                if vuln.is_exploited():
                    if vuln.exploitability == vuln.cvss / 5.5:
                        vuln.exploitability = (1 - vuln.exploitability) / 2 + vuln.exploitability
                        if vuln.exploitability > 1:
                            vuln.exploitability = 1
                        # todo: record vulnerability roa, impact, and complexity
                        self.adversary.get_network().get_scorer().add_vuln_compromise(self.env.now, vuln)
                        # self.scorer.add_vuln_compromise(self.curr_time, vuln)
            self.update_compromise_progress(self.env.now, self._proceed_time, self._scan_neighbors)
            
            # self._scan_neighbors()
        else:
            self._brute_force()

    def _execute_brute_force(self):
        """
        Tries bruteforcing a login for a short period of time using previous passwords from compromised user accounts to guess a new login.
        Checks if credentials for a user account has been successfully compromised.
        Phase 3
        """
        adversary = self.adversary
        _brute_force_result = adversary.get_curr_host().compromise_with_users(
            adversary.get_compromised_users())
        if _brute_force_result:
            self.update_compromise_progress(self.env.now, self._proceed_time, self._scan_neighbors)
            # self._scan_neighbors()
        else:
            self._enum_host()

    def _execute_scan_neighbors(self):
        """
        Starts scanning for neighbors from a host that the hacker can pivot to
        Puts the new neighbors discovered to the start of the host stack.
        """
        # logging.info("NEIGHBOUR SCANNING FIRST LINE")
        adversary = self.adversary
        if adversary.get_curr_host() is None:
            logging.warning("Adversary: Attempted to scan neighbors, but no current host is set.")
            return
        found_neighbors = adversary.get_curr_host().discover_neighbors()
        # logging.info(f"Found neighbors of current host: {found_neighbors}")
        
        new__host_stack = found_neighbors + [
            node_id
            for node_id in adversary.get_host_stack()
            if node_id not in found_neighbors
        ]
        # logging.info(f"Updated host stack after neighbor scan: {new__host_stack}")
        
        adversary.set_host_stack(new__host_stack)
        self._enum_host()
    
    def _execute_check_reachable(self):
        """
        Given a target Node is already compromised, check to see if the node is reachable.
        Utelise any compromsied nodes to assess a pathway towards target node, if no pathway is present, launch an attack.
        If a compromsied pathway exists, current attack is successful. 
        """
        # logging.info("Executing check_reachable")
        adversary = self.adversary
        network = adversary.get_network()
        
        # Gather all compromised nodes
        compromised_hosts = adversary.get_compromised_hosts()
        # logging.info(f"Compromised Hosts: {compromised_hosts}")
        
        # Check if the target node is among the compromised hosts
        if self.targetNode not in compromised_hosts:
            if self.logging:
                logging.info(f"Target node {self.targetNode} is not compromised yet.")
            self._scan_host()
            return
        
        # Use a BFS to check if there's a path from any compromised node to the target node
        visited = set()
        queue = []
        
        # Start with all compromised nodes
        for host in compromised_hosts:
            queue.append(host)
            visited.add(host)
        
        found_path = False
        
        while queue:
            current_host = queue.pop(0)
            
            # If we reached the target node, we found a path
            if current_host == self.targetNode:
                found_path = True
                break
            
            # Explore the neighbors
            for neighbor in network.get_neighbors(current_host):
                if neighbor not in visited and neighbor in compromised_hosts:
                    queue.append(neighbor)
                    visited.add(neighbor)
        
        if found_path:
            if self.logging:
                logging.info(f"Path to target node {self.targetNode} found through compromised nodes.")
            self.add_successful_attack()
            self.move_to_next_attack()
        else:
            if self.logging:
                logging.info(f"Target node {self.targetNode} is compromised but unreachable. Initiating scan to continue.")
            self.adversary.set_curr_host_id(-1)
            self.adversary.set_curr_host(None)
            if self.logging:
                logging.info('Adversary: Restarting with SCAN_HOST to Search for Compromised Target Node.')
            self._scan_host()

    def _set_next_pivot_host(self):
        """
        Sets the next host that the Hacker will pivot from to compromise other hosts
        The pivot host needs to be a compromised host that the hacker can access
        """
        adversary = self.adversary
        neighbors = list(adversary.get_network().get_neighbors(adversary.get_curr_host_id()))
        if adversary.get_pivot_host_id() in neighbors:
            return
        for n in neighbors:
            if n in adversary.get_compromised_hosts():
                adversary.set_pivot_host_id(n)
                return
        adversary.set_pivot_host_id(-1)

    def update_compromise_progress(self, now, proceed_time, nextAttack):
        """
        Updates the Hackers progress state when it compromises a host.
        """
        adversary = self.adversary
        adversary._pivot_host_id = adversary.get_curr_host_id()
        if adversary.get_curr_host_id() not in adversary.get_compromised_hosts():
            adversary.get_compromised_hosts().append(adversary.get_curr_host_id())
            self.adversary.compromisedIps.append(adversary.network.get_host(adversary.get_curr_host_id()).get_ip())
            if self.logging:
                logging.info("Current Compromised Hosts: ")
                logging.info(adversary.get_compromised_hosts())
                logging.info("Current Compromised IP addresses: ")
                logging.info(self.adversary.compromisedIps)
            
            adversary.get_attack_stats().update_compromise_host(adversary.curr_host)
            if self.logging:
                logging.info(
                "Adversary: Host %i has been compromised at %.1fs!" % (
                    adversary.get_curr_host_id(), now + proceed_time))
            adversary.get_network().update_reachable_compromise(
                adversary.get_curr_host_id(), adversary.get_compromised_hosts())

            for user in adversary.get_curr_host().get_compromised_users():
                if user not in adversary.get_compromised_users():
                    adversary.get_attack_stats().update_compromise_user(user)
            adversary._compromised_users = list(set(
                adversary.get_compromised_users() + adversary.get_curr_host().get_compromised_users()))

            # Check if the compromised host is the target node
            if adversary.get_curr_host_id() == self.targetNode:
                if self.logging:
                    logging.info(f"Target node {self.targetNode} has been compromised!")
                self.adversary.compromisedIps.append(self.targetIp)
                self.add_successful_attack()
                self.move_to_next_attack()
                return
            else:
                nextAttack()

            if adversary.get_network().is_compromised(adversary.get_compromised_hosts()):
                self.end_event.succeed()
                return
        else:
            nextAttack()
    
    def add_successful_attack(self):
        adversary = self.adversary
        start_time = self.env.now + self._proceed_time
        current_attack = {
        "process": adversary.get_curr_process(),
        "host_id": adversary.get_curr_host_id(),
        "host_ip": adversary.get_curr_host().get_ip() if adversary.get_curr_host() else None,
        "start_time": start_time,
        }
        
        self.adversary.successfulAttack.append(current_attack)
        self.adversary.successfulCount += 1
        return
        

    def get_proceed_time(self):
        return self._proceed_time

    def set_proceed_time(self, proceed_time):
        self._proceed_time = proceed_time

    def get_attack_process(self):
        return self._attack_process

    def set_attack_process(self, attack_process):
        self._attack_process = attack_process

    def set_interrupted_mtd(self, mtd):
        self._interrupted_mtd = mtd

    def get_adversary(self):
        return self.adversary
