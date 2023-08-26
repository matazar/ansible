import argparse
import subprocess


class unifi(object):
    """
    Creates and executes the commands requires to install SSL certificates
    in Unifi Network and Unifi Video.
    """
    def __init__(self, cert_name, verbose=False):
        """
        Set up the variables, check for errors, build commands.
        """
        self.verbose = verbose
        self.cert_name = cert_name
        # Variable to hold all the commands
        self.cmds = []
        self.network_cmds()

    def __call__(self):
        """
        Execute all the commands.
        """
        if self.verbose:
            print(f'Importing {self.cert_name} certificates into Unifi.')
        for cmd in self.cmds:
            if self.verbose:
                print(f'command: {" ".join(cmd)}')
            self.run(cmd)

    def run(self, cmd_list):
        """
        Executes the provided command using subprocess.
        stdout/stderr only show when verbose is enabled.
        """
        results = subprocess.run(cmd_list, capture_output=True)
        if self.verbose:
            print('command: %s' % (' '.join(results.args)))
            print('stdout: %s' % (results.stdout.decode('UTF-8')))
            if results.stderr:
                print('stderr: %s' % (results.stderr.decode('UTF-8')))

    def network_cmds(self):
        """
        Creates the commands required to install the certificate
        within Unifi Network.
        """
        # Convert certificate to .p12
        self.cmds.append(['/usr/bin/openssl', 'pkcs12', '-export',
                          '-inkey', '/etc/letsencrypt/live/%s/privkey.pem'
                          % (self.cert_name),
                          '-in', '/etc/letsencrypt/live/%s/fullchain.pem'
                          % (self.cert_name),
                          '-out', '/etc/letsencrypt/live/%s/fullchain.p12'
                          % (self.cert_name),
                          '-name', 'unifi', '-password', 'pass:unifi'])
        # Import certificate into Unifi Network
        self.cmds.append(['/usr/bin/keytool', '-importkeystore',
                          '-deststorepass', 'aircontrolenterprise',
                          '-destkeypass', 'aircontrolenterprise',
                          '-destkeystore', '/data/unifi/data/keystore',
                          '-srckeystore',
                          '/etc/letsencrypt/live/%s/fullchain.p12'
                          % (self.cert_name),
                          '-srcstoretype', 'PKCS12', '-srcstorepass',
                          'unifi', '-noprompt'])
        # Restart Unifi Network
        self.cmds.append(['/usr/sbin/service', 'unifi-core', 'restart'])
        self.cmds.append(['/usr/sbin/service', 'unifi', 'restart'])


def main():
    # Create menu with argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose',
                        help='Enable verbose output.',
                        action='store_true')
    parser.add_argument('cert_name',
                        help='Name of the Let\'s Encrypt Certificate.')
    parser.parse_args()
    args = parser.parse_args()

    # Run the function
    c = unifi(args.cert_name, args.verbose)
    c()


main()
