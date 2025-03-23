GNS3_VM = '192.168.33.7'
VM_USERNAME = 'gns3'
VM_PASSWORD = 'gns3'
PROJECT_ID = 'b816acbc-4962-40c4-a48a-bf80fa1aa2f9'

# http://192.168.33.7:3080/v2/projects/31d6b89d-08f6-4eba-8d7d-0ed7a19579b4/nodes view nodes in case ids change TODO: script for automatically extracting ids
DOCKER_NODES = {
    "AdminPC": "1a93b4113186",
    "COZYBEAR": "2aad6fbd7fa6",
    "IDPS": "51298fb32cfa", 
    "RepoServer": "52bc3f6857af",
    "MgmHost": "e6111d7557a1",
    "Fileshare": "5e56b4235ac1"
}

GNS3_NODES = {
    "AdminPC": "52285f4f-b1e8-415a-9b0b-4777b3a69a9d",
    "MgmHost": "dffb290d-5f24-4410-b434-e187db112f51",
    "Fileshare": "4165ae64-eb21-47c1-9b87-d57cd721fa66",
    "RepoServer": "ea423931-3d64-45f2-9103-5bf599e5137c",
    "IDPS": "46e1a433-884d-4900-84e8-ef2a8b35343e"
}

IP_ADDRESS_MAP = {
    "10.0.0.2": 0,
    "172.17.100.2": 1,
    "192.168.100.2": 2,
    "192.168.100.3": 3,
    "192.42.0.10": 4,
}

REVERSE_IP_ADDRESS_LIST = ["10.0.0.2", "172.17.100.2", "192.168.100.2", "192.168.100.3", "192.42.0.10"]

ALERT_MAP = {
    "ICMP PING NMAP": 0,
    "SNMP request tcp": 1,
    "SNMP AgentX/tcp request": 2,
    "SCAN nmap XMAS": 3,
    "SSH Brute-Force Detected": 4,
    "Malicious Script Detected - Unauthorized User Creation": 5
}

# Console commands
BRUTE_FORCE_ATTACK = 'medusa -h %s -U users.txt -P passwords.txt -M ssh | grep FOUND'

NMAP_SCAN = "nmap -sS -sV -O -oX -"

ADDRESS_MAP = {
    #RepoServer
    '172.17.100.2': 0,
    #AdminPC
    '192.168.100.2': 1,
    #Fileshare
    '192.168.100.3': 2,
}

REVERSE_ADDRESS_MAP = ['172.17.100.2', '192.168.100.2', '192.168.100.3']

HOST_MAP = ["RepoServer", "AdminPC", "Fileshare", "COZYBEAR"]

DEFENSE_NODES = ["RepoServer", "AdminPC", "Fileshare", "IDPS"]

DEFENSE_NODES_MAP = {
    "RepoServer": 0, 
    "AdminPC": 1, 
    "Fileshare": 2,
    "IDPS": 3
    }

ADDRESS_LIST = ['172.17.100.2', '192.168.100.2', '192.168.100.3']

CRITICAL_INDEX_MAP = {
    "RepoServer": 4.2,
    "AdminPC": 1.6,
    "Fileshare": 2.8,
    "IDPS": 5,
}