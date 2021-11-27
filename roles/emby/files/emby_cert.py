# Script to convert Let's Encrypt certificates for use and restart Emby servers.

import argparse
import subprocess


class emby(object):
    """
    Creates and executes the commands requires to convert an SSL certificate
    for use with Emby.
    """
    def __init__(self, cert_name, verbose=False):
        """
        Set up the variables, check for errors, build commands.
        """
        self.verbose = verbose
        self.cert_name = cert_name
        # Variable to hold all the commands
        self.cmds = []
        # Create the required commands
        self.cert_cmds()
        
    def __call__(self):
        """
        Execute all the commands.
        """
        for cmd in self.cmds:
            self.run(cmd)

    def run(self, cmd_list):
        """
        Executes the provided command using subprocess.
        stdout/stderr only show when verbose is enabled.
        """
        stdout, stderr = False, False
        results = subprocess.run(cmd_list, capture_output=True)
        if self.verbose:
            print('command: %s' % (' '.join(results.args)))
            print('stdout: %s' % (results.stdout.decode('UTF-8')))
            if results.stderr:
                print('stderr: %s' % (results.stderr.decode('UTF-8')))
    
    def cert_cmds(self):
        """
        Creates the commands required to convert the cert for use with Emby.
        """
        # Convert certificate to .p12
        self.cmds.append(['/usr/bin/openssl', 'pkcs12', '-export',
                          '-inkey', '/etc/letsencrypt/live/%s/privkey.pem' % (self.cert_name),
                          '-in', '/etc/letsencrypt/live/%s/fullchain.pem' % (self.cert_name),
                          '-out', '/etc/letsencrypt/live/%s/fullchain.p12' % (self.cert_name),
                          '-password', 'pass:'])

        # Restart Unifi Network
        self.cmds.append(['/usr/sbin/service', 'emby-server', 'restart'])

def main():
    # Create menu with argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Enable verbose output.', action='store_true')
    parser.add_argument('cert_name', help='Name of the Let\'s Encrypt Certificate.')
    parser.parse_args()
    args = parser.parse_args()

    # Run the function
    c = emby(args.cert_name, args.verbose)
    c()


main()

