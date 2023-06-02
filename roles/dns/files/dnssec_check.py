# Checks DNSSEC domains and signs any that will expire soon.

import argparse
import subprocess
import re
import datetime
import secrets
import sys


class Domains(object):
    """
    Get a list of domains from the config file.
    """
    def __init__(self, config_file, verbose=False):
        """
        Set verbosity and load the domains into a list variable.
        """
        self.verbose = verbose
        # Load the options as a dict.
        self.domains = self.load_domains(config_file)

    def __call__(self):
        """
        Return the list of domains.
        """
        return self.domains

    def load_domains(self, config_file):
        """
        Load the domains from a "config" file.
        """
        # Just in case the config file doesn't exist.'
        try:
            c = open(config_file, 'r')
        except FileNotFoundError:
            sys.exit('\nDomain list file %s doesn\'t exist.' % (config_file))
        domains = []
        # Each line of the config file should contain a domain.
        for line in c.readlines():
            # Filter out comment lines
            if not line.startswith("#"):
                # Strip newline and whitespace from entries to be safe.
                domain = line.strip('\n')
                domains.append(domain.strip(' '))
        return domains


class DNSSEC(object):
    """
    Runs commands to check DNSSEC domains for when they expire and
    run the command to sign them again when necessary.
    """
    def __init__(self, config_file, days=5, verbose=False):
        """
        Get the domains from the "config" file and set basic settings.
        """
        self.verbose = verbose
        self.sign_days = int(days)
        self.config_file = config_file
        self.domains = Domains(self.config_file, verbose=False)
        self.now = datetime.datetime.now()

    def __call__(self):
        """
        Check each domain and sign if below the threshold.
        """
        # Regex to pull dnssec expiry date
        rrsig_regex = re.compile(
            r'RRSIG (?:A|aaaa|NSEC) \d{1,2} \d \d{3,7} \(\s+(\d{14}) (\d{14})')
        # Get our domain list
        domain_list = self.domains()
        # Always warn if the list is empty
        if len(domain_list) == 0:
            print('\nNo domains listed in %s\n' % (self.config_file))
        for domain in domain_list:
            if self.verbose:
                print('Checking domain: %s\n' % (domain))
            # Use dig to fetch the DNSSEC record info.
            results = self.run(['dig', domain, '+dnssec', '+multi'])
            dates = rrsig_regex.search(results['stdout'])
            if dates:
                # Get expiry date as datetime object
                exp_date = self.rrsig_dates(dates.groups(0))
                if self.verbose:
                    print('\n%s is set to expire on %s' % (domain, exp_date))
                # Figure out how many days are left and if we should sign now.
                exp_days = exp_date - self.now
                if int(exp_days.days) <= self.sign_days:
                    # Sign the domain
                    result = self.sign_domain(domain)
                    if result['rc'] == 0:
                        print('%s was signed.' % (domain))
                    else:
                        # Output errors when things don't work out.
                        print('Errors while signing %s:' % (domain))
                        print('\n' + result['stderr'])
            else:
                # Missing RRSIG, warn even with quiet mode.
                print('Domain %s has no RRSIG record.' % (domain))

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
        return {'stdout': results.stdout.decode('UTF-8'),
                'stderr': results.stderr.decode('UTF-8'),
                'rc': results.returncode}

    def rrsig_dates(self, dates):
        """
        Returns the dates from the RRSIG date
        """
        exp = datetime.datetime.strptime(dates[0], '%Y%m%d%H%M%S')
        return exp

    def sign_domain(self, domain):
        """
        Sign the domain.
        """
        # Generate our salt
        salt = secrets.token_hex(8)
        # Set up the command
        signzone_cmd = ['/usr/sbin/dnssec-signzone', '-A', '-3', salt, '-N',
                        'INCREMENT', '-K', '/var/cache/bind/', '-o', domain,
                        '-t', '/var/lib/bind/%s.db' % (domain)]
        # Run it
        result = self.run(signzone_cmd)
        # Return the results
        return result


def main():
    """
    Set up the cli menu and run the script.
    """
    # cli menu
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Enable verbose output.',
                        action='store_true')
    parser.add_argument('-d', '--days', default=5,
                        help='Days before domain expiry to sign.')
    parser.add_argument('domain_list', default='/root/.dnssec_domains.conf',
                        nargs='?',
                        help='Path to list of DNSSEC domains. ' +
                        'Default ~/.dnssec_domains.conf')
    parser.parse_args()
    args = parser.parse_args()

    # Run it
    d = DNSSEC(args.domain_list, args.days, args.verbose)
    d()


main()
