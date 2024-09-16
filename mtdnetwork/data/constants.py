# Global constants for the simulation

OS_TYPES = [
    "windows",
    "ubuntu",
    "centos",
    "freebsd"
]

OS_VERSION_DICT = {
    "windows": ["10", "8.1", "8", "7", "vista", "xp"],
    "ubuntu": ["20.04", "18.04", "16.04", "14.04", "12.04", "10.04"],
    "centos": ["8", "7", "6", "5", "4", "3"],
    "freebsd": ["13", "12", "11", "10", "9", "8"]
}

HOST_TAGS = [
    "web",
    "db",
    "application",
    "file",
    "mail",
    "untagged",
    "Host_tag_fill1",
    "Host_tag_fill2",
    "Host_tag_fill3",
    "Host_tag_fill4",
    "Host_tag_fill5",
    "Host_tag_fill6"
]

NODE_COLOURS = [
    "green",
    "blue",
    "yellow",
    "purple",
    "orange",
    "pink",
    "brown"
]

SERVICE_VERSIONS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                    53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77,
                    78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99]

LARGE_INT = (1 << 100)

# No longer used and wordlists are included part of the package
# WORDLIST_URL = "https://www.mit.edu/~ecprice/wordlist.10000"
# NAME_LIST_URL = "https://raw.githubusercontent.com/dominictarr/random-name/master/first-names.txt"

# Constants for MTD strategies
# MTD_MIN_TRIGGER_TIME = 1000
# MTD_MAX_TRIGGER_TIME = 5000

# Constants about users

USER_TO_NODES_RATIO = 1
USER_PROB_TO_REUSE_PASS = 0.05
USER_TOTAL_FOR_EACH_HOST = 5

# Constants for Network
# NETWORK_HOST_DISCOVER_TIME = 1

# Constants for Hosts
HOST_SERVICES_MIN = 3
HOST_SERVICES_MAX = 11
HOST_INTERNAL_SERVICE_MIN = 0
HOST_PORT_RANGE = range(1, 65546)
HOST_MAX_PROB_FOR_USER_COMPROMISE = 0.01
# HOST_USER_COMPROMISE_TIME = 5
# HOST_AUTO_COMPROMISE_TIME = 1
# HOST_PORT_SCAN_MIN_TIME = 10
# HOST_PORT_SCAN_MAX_TIME = 50

# Constants for Vulns
VULN_MAX_PROB_FOR_OCCURING_FOR_SERVICE_VERSION = 0.10
VULN_INITIAL_CHANCES = 100
VULN_PATCH_MEAN = 10
VULN_PATCH_RANGE = 9
# VULN_PERCENT_CROSS_PLATFORM = 0.5
VULN_PERCENT_CROSS_PLATFORM = 0.5
# VULN_PROB_DEPENDS_ON_OS = 0.1
VULN_PROB_DEPENDS_ON_OS = 0.8
VULN_PROB_DEPENDS_ON_OTHER_VULNS = 0.1
VULN_MIN_EXPLOIT_TIME = 10
VULN_MAX_EXPLOIT_TIME = 200
VULN_MIN_COMPLEXITY = 0.4

# Constants for Services
SERVICE_NO_OF_SERVICES_PER_OS = 20
SERVICE_COMPROMISED_THRESHOLD = 7
SERVICE_DISCOVER_EACH_VULN_TIME = 10
SERVICE_TOP_X_VULNS_TO_RETURN = 5

#  Constants for Attackers
# HACKER_BLOCKED_BY_MTD_PENALITY = 1000
# HACKER_BLOCKED_BY_MTD_MAX_DISCOUNT = 0.9
# HACKER_BLOCKED_BY_MTD_BLOCKS_TO_MAX_DISCOUNT = 75
# HACKER_HOP_TIME = 5
HACKER_ATTACK_ATTEMPT_MULTIPLER = 5

# Constants for Runtime
STANDARD_ERROR_BENCHMARK_PERCENT = 5
ATTACKER_THRESHOLD = 10

# Constants for MTD scheme
# scheme : (mean, std)
MTD_TRIGGER_INTERVAL = {
    'simultaneous': (700, 0.5),
    'random': (200, 0.5),
    'alternative': (200, 0.5)
}

# mtd name : priority value
MTD_PRIORITY = {
    'CompleteTopologyShuffle': 1,
    'HostTopologyShuffle': 2,
    'IPShuffle': 3,
    'OSDiversity': 4,
    'PortShuffle': 5,
    'ServiceDiversity': 6,
    'UserShuffle': 7,
}

# mtd name : (mean, std)
MTD_DURATION = {
    'CompleteTopologyShuffle': (120, 0.5),
    # 'HostTopologyShuffle': (100, 0.5),
    'IPShuffle': (110, 0.5),
    'OSDiversity': (80, 0.5),
    'ServiceDiversity': (70, 0.5),
    # 'PortShuffle': (70, 0.5),
    # 'UserShuffle': (20, 0.5)
}

# Constants for attack processes
# may need to combine with "Constants for Attackers" for future works
ATTACK_DURATION = {
    'SCAN_HOST': 5,
    'ENUM_HOST': 5,
    'SCAN_NEIGHBOR': 5,
    'SCAN_PORT': 25,
    'EXPLOIT_VULN': 15,
    'BRUTE_FORCE': 20,
    'PENALTY': 20,
    'CHECK_REACHABLE': 15,
}
