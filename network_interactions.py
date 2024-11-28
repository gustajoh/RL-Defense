import paramiko
import requests
import constants

ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


def execute_command(node_id, command):
    try:
        # Connect to the GNS3 VM
        ssh_client.connect(hostname=constants.GNS3_VM,
                           username=constants.VM_USERNAME, password=constants.VM_PASSWORD)
        print("SSH connection established successfully!")

        exec_command = f'docker exec -i {node_id} {command}'
        _, stdout, stderr = ssh_client.exec_command(exec_command)
        output = stdout.read().decode('utf-8')
        #print("output:", output)

        error = stderr.read().decode('utf-8')
        if error:
            print("Error output:\n", error)
        return output

    except paramiko.AuthenticationException:
        print("Authentication failed, please verify your credentials.")
    except paramiko.SSHException as sshException:
        print(f"Unable to establish SSH connection: {sshException}")
    except Exception as e:
        print(f"Exception in connecting: {e}")
    finally:
        # Close connection
        ssh_client.close()
        print("SSH connection closed.")


def start_node(node):
    URL = ('http://192.168.33.7:3080/v2/projects/'
           f'{constants.PROJECT_ID}/nodes/{node}/start')
    response = requests.post(
        URL,
        headers={'Content-Type': 'application/x-www-form-urlencoded', }
    )
    return response


def stop_node(node):
    URL = ('http://192.168.33.7:3080/v2/projects/'
           f'{constants.PROJECT_ID}/nodes/{node}/stop')
    response = requests.post(
        URL,
        headers={'Content-Type': 'application/x-www-form-urlencoded', }
    )
    return response


def restart_node(node):
    start_url = ('http://192.168.33.7:3080/v2/projects/'
                 f'{constants.PROJECT_ID}/nodes/{node}/start')
    stop_url = ('http://192.168.33.7:3080/v2/projects/'
                f'{constants.PROJECT_ID}/nodes/{node}/stop')

    response1 = requests.post(
        stop_url,
        headers={'Content-Type': 'application/x-www-form-urlencoded', }
    )

    response2 = requests.post(
        start_url,
        headers={'Content-Type': 'application/x-www-form-urlencoded', }
    )

    return (response1, response2)
