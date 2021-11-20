# Script to import Let's Encrypt certificates into the unifi services.
# Should work as a deploy_hook python3 unifi_cert.py network <cert folder name>

import argparse
import subprocess


class unifi(object):
    """
    Creates and executes the commands requires to install SSL certificates
    in Unifi Network and Unifi Video.
    """
    def __init__(self, unifi_type, cert_name, verbose=False):
        """
        Set up the variables, check for errors, build commands.
        """
        self.verbose = verbose
        self.cert_name = cert_name
        self.unifi_type = unifi_type
        # Variable to hold all the commands
        self.cmds = []
        # Create the required commands
        if self.unifi_type in ['network', 'all']:
            print('Network')
            self.network_cmds()
        if self.unifi_type in ['video', 'all']:
            print('Video')
            self.video_cmds()

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
        # print('Command: %s' % (' '.join(cmd_list)))
        results = subprocess.run(cmd_list, capture_output=True)
        if self.verbose:
            print('command: %s' % (' '.join(results.args)))
            print('stdout: %s' % (results.stdout.decode('UTF-8')))
            if results.stderr:
                print('stderr: %s' % (results.stderr.decode('UTF-8')))
    
    def network_cmds(self):
        """
        Creates the commands required to install the certificate within Unifi Network.
        """
        # Convert certificate to .p12
        self.cmds.append(['/usr/bin/openssl', 'pkcs12', '-export',
                          '-inkey', '/etc/letsencrypt/live/%s/privkey.pem' % (self.cert_name),
                          '-in', '/etc/letsencrypt/live/%s/fullchain.pem' % (self.cert_name),
                          '-out', '/etc/letsencrypt/live/%s/fullchain.p12' % (self.cert_name),
                          '-name', 'unifi', '-password', 'pass:unifi'])
        # Import certificate into Unifi Network
        self.cmds.append(['/usr/bin/keytool', '-importkeystore', '-deststorepass', 'aircontrolenterprise',
                          '-destkeypass', 'aircontrolenterprise', '-destkeystore', '/var/lib/unifi/keystore',
                          '-srckeystore', '/etc/letsencrypt/live/%s/fullchain.p12' % (self.cert_name),
                          '-srcstoretype', 'PKCS12', '-srcstorepass', 'unifi', '-noprompt'])
        # Restart Unifi Network
        self.cmds.append(['/usr/sbin/service', 'unifi', 'restart'])


    def video_cmds(self):
        """
        Creates the commands required to install the certificate within Unifi Video.
        """
        # Convert certificate to .der
        self.cmds.append(['/usr/bin/openssl', 'x509', '-outform', 'der',
                          '-in', '/etc/ssl/unifi_video/%s/cert.pem' % (self.cert_name),
                           '-out', '/usr/lib/unifi-video/data/certificates/ufv-server.cert.der'])
        # Convert private key to .der
        self.cmds.append(['/usr/bin/openssl', 'pkcs8', '-topk8', '-inform', 'PEM', '-outform', 'DER',
                          '-in', '/etc/ssl/unifi_video/%s/privkey.pem' % (self.cert_name),
                          '-out', '/usr/lib/unifi-video/data/certificates/ufv-server.key.der',
                          '-nocrypt'])
        # Ensure we have the correct ownership on the new certificate files
        self.cmds.append(['/usr/bin/chown', '-R', 'unifi-video:unifi-video', 
                          '/usr/lib/unifi-video/data/certificates/'])
        # Restart Unifi Video to import certificates
        self.cmds.append(['/usr/sbin/service', 'unifi-video', 'restart'])


def main():
    # Create menu with argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Enable verbose output.', action='store_true')
    parser.add_argument('unifi_type', choices=['network', 'video', 'all'], help='Unifi service type.')
    parser.add_argument('cert_name', help='Name of the Let\'s Encrypt Certificate.')
    parser.parse_args()
    args = parser.parse_args()

    # Run the function
    c = unifi(args.unifi_type, args.cert_name, args.verbose)
    c()


main()

