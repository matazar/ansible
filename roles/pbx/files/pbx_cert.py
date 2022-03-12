# Script to move Let's Encrypt certificate for use with Asterisk.

import argparse
import subprocess


class pbx(object):
    """
    Copies and executes the commands requires to set an SSL certificate
    for use with Asterisk PBX.
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
            self.run(cmd.split(' '))

    def run(self, cmd_list):
        """
        Executes the provided command using subprocess.
        stdout/stderr only show when verbose is enabled.
        """
        stdout, stderr = False, False
        results = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if self.verbose:
            print('command: %s' % (' '.join(cmd_list)))
            print('stdout: %s' % (results.stdout.decode('UTF-8')))
            if results.stderr:
                print('stderr: %s' % (results.stderr.decode('UTF-8')))
    
    def cert_cmds(self):
        """
        Creates all the commands we need to import the certificate into Asterisk.
        """
        # Copy certs to folders.
        self.cmds.extend(['cp /etc/letsencrypt/live/%s/cert.pem /etc/asterisk/%s.test' % 
                            (self.cert_name, self.cert_name), # This is for the playbook test.
                          'cp /etc/letsencrypt/live/%s/cert.pem /etc/asterisk/keys/%s.crt' % 
                            (self.cert_name, self.cert_name),
                          'cp /etc/letsencrypt/live/%s/privkey.pem /etc/asterisk/keys/%s.key' % 
                            (self.cert_name, self.cert_name)])
        # Deal with ownership and permissions
        self.cmds.extend(['chmod -R 0700 /etc/asterisk/keys/',
                          'chown -R asterisk:asterisk /etc/asterisk/keys/'])
        # Handle Asterisk commands
        self.cmds.extend(['fwconsole certificate --import',
                          'fwconsole certificate --default=0',
                          'fwconsole sysadmin installHttpsCert default',
                          'fwconsole sysadmin updatecert'])

def main():
    # Create menu with argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Enable verbose output.', action='store_true')
    parser.add_argument('cert_name', help='Name of the Let\'s Encrypt Certificate.')
    parser.parse_args()
    args = parser.parse_args()

    # Run the function
    c = pbx(args.cert_name, args.verbose)
    c()


main()

