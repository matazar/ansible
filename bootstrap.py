#!/usr/bin/env ./bin/python

"""
Bootstraps Debian based ansible host.
./bootstrap.py <ip/hostname>
"""

import argparse
import sys
import os
import re
import socket
import getpass
from fabric import Connection, Config


class bootstrap(object):
    def __init__(self, args):
        """
        Sets up the environment and create a list of hosts to bootstrap.
        """
        self.env = False
        self.ssh_key = self.set_ssh_key()
        self.hosts = self.parse_hosts(args.host)

    def __call__(self):
        """
        Prepares each host for ansible plays.
        """
        for host in self.hosts:
            # Prompt for crendentials
            user = input('Username for %s: ' % (host))
            password = getpass.getpass('Password for %s@%s: ' % (user, host))
            if user == 'root':
                c = Connection(self.hosts[host],
                               user=user, 
                               connect_kwargs={"password": password})
                try:
                    c.run('apt install -y python3 python3-apt')
                except Exception as e:
                    print('Unable to install python with apt.')
                    print(e)
            else:
                config = Config(overrides={'sudo': {'password': password}})
                c = Connection(self.hosts[host],
                               user=user,
                               connect_kwargs={"password": password},
                               config=config)
                try:
                    c.sudo('apt install -y python3 python3-apt')
                except Exception as e:
                    print('Unable to install python with apt.')
                    print(e)
            # Ensure the host has a copy of our ssh key.
            c.run('mkdir -p .ssh')
            c.put(self.ssh_key)
            c.run('cat %s >> .ssh/authorized_keys' %
                  (self.ssh_key.rsplit('/', 1)[1]))
            c.close()
            # Provide copy/paste command to run bootstrap play.
            print(f'\n\nNow run:\nansible-playbook -i {self.inv_file} ' +
                  f'playbooks/bootstrap.yml -e "ansible_ssh_user={user}" -D -l {host}')

    def parse_hosts(self, hosts):
        """
        Ensure hosts is a list of acceptable hosts.
        """
        # We only want strings or lists.
        if type(hosts) not in [str, list]:
            sys.exit('Invalid host "%s"' % (hosts))
        if type(hosts) == str:
            # Convert a string into a list.
            hosts == [hosts]
        # Variable to keep hosts that pass tests
        results = {}
        # Ensure it's a hostname, ipv4 or ipv6
        ipv4 = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        ipv6 = re.compile(r'(?:^|(?<=\s))(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]'
                          r'{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}'
                          r':){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}'
                          r'(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}'
                          r'(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}'
                          r'(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}'
                          r'(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}'
                          r':((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4})'
                          r'{1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]'
                          r'{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]'
                          r'|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|'
                          r'1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}'
                          r':((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}'
                          r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?=\s|$)')
        hostname = re.compile(r'^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*'
                              r'[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z]'
                              r'[A-Za-z0-9\-]*[A-Za-z0-9])$',
                              re.IGNORECASE)
        for h in hosts:
            if re.match(ipv4, h):
                results[h] = h
            if re.match(ipv6, h):
                results[h] = h
            if re.match(hostname, h):
                # Find IP of host, assume DNS isn't set up.
                ip = self.inventory_lookup(h)
                if ip:
                    results[h] = ip.strip(' ')
        # Return a list of IPs to bootstrap.
        return results

    def inventory_lookup(self, host):
        """
        Search the env inventory file for the IP address of the hostname.
        If the host isn't found, attempt to resolve it instead.
        """
        if not self.env:
            self.set_env()
        self.inv_file = os.path.join('env', self.env, 'inventory.yml')
        inv = open(self.inv_file)
        # Loop through the file until we find the host line we want
        for line in inv.readlines():
            if line.startswith(host):
                m = re.search(r'ansible_host=(.+)', line)
                if m:
                    return m.group(1)
        print('Unable to find "%s" in %s' % (host, inv.name))
        # Try to resolve it through DNS
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            print('Unable to resolv "%s"' % (host))
        print('Skipping host %s\n' % (host))
        return False

    def set_env(self):
        """
        Prompt the user to select an environment from the existing folders.
        """
        # List our environment options
        env_dir = os.listdir('env/')
        # Ignore global env
        if 'global' in env_dir:
            env_dir.remove('global')
        i = 1
        env_opt = {}
        for e in env_dir:
            if os.path.isdir('env/%s' % (e)):
                # Display them for the user.
                print('%d. %s' % (i, e))
                env_opt[i] = e
                i += 1
        # Prompt them to select one.
        while not self.env:
            p = input('Select environment: \n')
            try:
                if int(p) in env_opt.keys():
                    self.env = env_opt[int(p)]
                    print('')
                    break
            except Exception as e:
                print(e)
            print('Invalid selection "%s", please choose again.' % (p))

    def set_ssh_key(self):
        """
        Prompts the user to select the ssh key they wish to bootstrap with.
        """
        # List user ssh key options
        ssh_dir = os.path.expanduser('~/.ssh/')
        ssh_contents = os.listdir(ssh_dir)
        i = 1
        ssh_keys = {}
        for key in ssh_contents:
            if key.endswith('.pub'):
                print('%d. %s' % (i, key))
                ssh_keys[i] = os.path.join(ssh_dir, key)
                i += 1
        # Prompt them to select one.
        while True:
            p = input('Select SSH Key: \n')
            try:
                if int(p) in ssh_keys.keys():
                    print('')
                    return ssh_keys[int(p)]
            except Exception as e:
                print(e)
            print('Invalid selection "%s", please choose again.' % (p))


def main():
    parser = argparse.ArgumentParser(description="Bootstrap ansible host")
    parser.add_argument(
        'host',
        nargs='+',
        type=str,
        help="Hostname or IP of host to be boostrapped.")

    args = parser.parse_args()
    b = bootstrap(args)
    b()
    sys.exit()


# if __name__ == '__main__':
main()
