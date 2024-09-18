GNS3_VM = '192.168.33.7'
VM_USERNAME = 'gns3'
VM_PASSWORD = 'gns3'
PROJECT_ID = '3317c6f6-5a8f-4a89-a09c-b59cae565e0d'

DOCKER_NODES = {
    "AdminPC": "27b7647b6071" ,
    "COZYBEAR": "bbfc0e11fd42",
    "IDPS" : "05ea4b2441c6",
    "RepoServer" : "5ba20cc85042",
    "MgmHost" : "2835fe355648",
    "Fileshare" : "5aaad19d7dca"
}

# Console commands
BRUTE_FORCE_ATTACK = 'medusa -h %s -U users.txt -P passwords.txt -M ssh | grep FOUND'