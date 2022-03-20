# Ansible Roles

A collection of my personal ansible roles with a few scripts to go with them. I use these to configure my mostly Debian servers and VMs. They can be used to deploy fully functioning Bind9 DNS, LDAP, Email (Postfix/Dovcecot/LDAP backend) servers, in addition to a few web applications I've deployed or tested out. The playbooks have only been testing using Vultr cloud instances and local physical hosts/VirtualBox VMs with manual OS installations.

# Configuring the environment

Before setting up a host, you will need to configure the various variables that power the roles. You can review the VARIABLES.md file to see a list of variables or look at the example environment folder found under env/example.

# Bootstrapping the hosts

You can bootstrap the hosts by using the bootstrap.py file, though you may need to update the path found at the top of the file as it is set to run from a virtual environment inside my ansible root folder. Fabric must be installed for it to work properly.

To bootstrap a host, ensure the host is found in the inventory file under the desired env, then run:

> ./bootstrap.py \<hostname\>  

e.g.:
> ./bootstrap.py cloud1.example.com

The python script will ensure python3 is installed on the host (if it's Debian based) and that the ssh key is configured for the bootstrap ssh user.

When the script finished, it will provide you with the command to complete the bootstrap process using ansible.
>Now run:  
ansible-playbook -i env/example/inventory.yml bootstrap.yml -e "ansible_ssh_user=admin" -K -D -l cloud1.example.com

# Roles
See ROLES.md file for a short description of each role.

# Variables
See VARIABLES.md file for descriptions and examples of the various variables.