GNS3_VM = '192.168.33.7'
VM_USERNAME = 'gns3'
VM_PASSWORD = 'gns3'
PROJECT_ID = '3317c6f6-5a8f-4a89-a09c-b59cae565e0d'

# http://192.168.33.7:3080/v2/projects/3317c6f6-5a8f-4a89-a09c-b59cae565e0d/nodes view nodes in case ids change TODO: script for automatically extracting ids
DOCKER_NODES = {
    "AdminPC": "27b7647b6071",
    "COZYBEAR": "bbfc0e11fd42",
    "IDPS": "05ea4b2441c6",
    "RepoServer": "5ba20cc85042",
    "MgmHost": "2835fe355648",
    "Fileshare": "5aaad19d7dca"
}

USERS = ['james', 'alica', 'bob']
# Console commands
BRUTE_FORCE_ATTACK = 'medusa -h %s -U users.txt -P passwords.txt -M ssh | grep FOUND'

# Todo: update with more appropriate rules for snort and shorewall
SNORT_RULES = ['alert icmp any any -> $HOME_NET any (msg:"ICMP Ping"; sid:1000001; rev:1;)',
               'alert tcp any any -> $HOME_NET 80 (msg:"HTTP Traffic"; sid:1000002; rev:1;)',
               'alert udp any any -> $HOME_NET 53 (msg:"DNS Query"; sid:1000003; rev:1;)']

SHOREWALL_RULES = [
    "ACCEPT   net      fw     tcp       80",
    "ACCEPT   net      fw     tcp       443",
    "DROP     net:192.168.1.100     all",
    "ACCEPT   lan      fw     tcp       22",
    "DROP     net:192.168.2.0/24    all",
    "ACCEPT   net      fw     icmp"
]
