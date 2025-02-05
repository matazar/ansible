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
        results = subprocess.run(cmd_list, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        if self.verbose:
            print('command: %s' % (' '.join(cmd_list)))
            print('stdout: %s' % (results.stdout.decode('UTF-8')))
            if results.stderr:
                print('stderr: %s' % (results.stderr.decode('UTF-8')))

    def cert_cmds(self):
        """
        Creates all the commands we need to import
        the certificate into Asterisk.
        """
        # Copy certs to folders.
        self.cmds.extend(
            [f'cp /etc/letsencrypt/live/{ self.cert_name }/cert.pem ' +
             f'/etc/asterisk/{ self.cert_name }.test'  # Playbook test.
             f'cp /etc/letsencrypt/live/{ self.cert_name }/cert.pem ' +
             f'/etc/asterisk/keys/{ self.cert_name }.crt',
             f'cp /etc/letsencrypt/live/{ self.cert_name }/privkey.pem ' +
             f'/etc/asterisk/keys/{ self.cert_name }.key'])
        # Deal with ownership and permissions
        self.cmds.extend(['chmod -R 0700 /etc/asterisk/keys/',
                          'chown -R asterisk:asterisk /etc/asterisk/keys/'])
        # Handle Asterisk commands
        self.cmds.extend(['/usr/sbin/fwconsole certificate --import',
                          '/usr/sbin/fwconsole certificate --default=0',
                          '/usr/sbin/fwconsole sysadmin installHttpsCert default',
                          '/usr/sbin/fwconsole sysadmin updatecert'])


def main():
    # Create menu with argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Enable verbose output.',
                        action='store_true')
    parser.add_argument('cert_name',
                        help='Name of the Let\'s Encrypt Certificate.')
    parser.parse_args()
    args = parser.parse_args()

    # Run the function
    c = pbx(args.cert_name, args.verbose)
    c()


main()
