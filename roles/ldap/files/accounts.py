import ldap3
import datetime
import getpass
from ldap3.utils.hashed import hashed
import argparse
import configparser
import sys
import os


config_file = "~/.ldap.conf"
default_config = """
; Example configuration
; [example]
; ldap_user = cn=admin,dc=example,dc=com
; ldap_pw = SpareDormHousePass
; ldap_server = ldap.example.com
; ldap_basedn = dc=example,dc=com
; ldap_port = 389
; ldap_tls = True
"""

class Settings(object):
    def __init__(self, config_file=config_file, env=False, verbose=False):
        self.verbose = verbose
        self.env = env
        self.config_file = self.check_config(config_file)
        # Load the options as a dict.
        self.options = dict(self.load_config())

    def __call__(self, key):
        # Return the value requested
        return self.options[key]

    def load_config(self):
        """
        Load the config file, or create one if it doesn't exist and prompt the user
        for the information for this run.
        """
        config = configparser.ConfigParser()
        config.read(self.config_file)

        # Ensure env exists, if provided.
        if self.env:
            if self.env in config.sections():
                i = dict(config.items(self.env))
            else:
                # Warn the user and reset the env if the one provided doesn't exist in the config.
                print('\nEnvironment "%s" not defined in %s' % (self.env, self.config_file))
                self.env = False
        if not self.env:
            # Prompt user if nothing is defined in the config file.
            if len(config.sections()) <= 0:
                self.env = ''
                if self.verbose:
                    print('No LDAP settings found in %s.' % (self.config_file))
                    print('Enter the details below to save them to the config file.')
                # Prompt the user for LDAP details
                prompts = {
                        'ldap_server': 'LDAP server',
                        'ldap_port': 'LDAP Port',
                        'ldap_tls': 'Use TLS',
                        'ldap_basedn': 'LDAP Base DN',
                        'ldap_user': 'LDAP Bind DN',
                        'password': 'LDAP Password'
                }
                i = get_user_input(prompts)
                # Update LDAP password var and remove 'password' entry
                i['ldap_pw'] = i['password']
                del i['password']
                # Save details to config file
                self.save_config(i)
            # Default when only 1 environment exists.
            elif len(config.sections()) == 1:
                self.env = config.sections()[0]
                if self.verbose:
                    print('\nDefaulting to %s as it\'s the only environment in config file.' %
                            (self.env))
                i = dict(config.items(self.env))
            # Prompt the user when multiple environments exist.
            else:
                c = 0
                print('\nSelect config environment: ')
                for e in config.sections():
                    print('%s. %s' % (c,e))
                    c += 1
                i = input('')
                self.env = config.sections()[int(i)]
                i = dict(config.items(self.env))
        return i

    def save_config(self, options):
        """
        Saves entered data to the config file.
        """
        f = open(self.config_file, 'a')
        env = input('Save as environment: ')
        f.write('\n[%s]\n' % (env))
        for k in options:
            f.write('%s = %s\n' % (k, options[k]))
        f.close()
    
    def check_config(self, config_file):
        """
        Ensure config file exists, otherwise create a commented example for the user.
        """
        path = os.path.expanduser(config_file)
        if not os.path.exists(path):
            f = open(path, 'w')
            f.write(default_config)
            f.close()
            print('\nDefault config file created at %s.' % (path))
        return path


class ManageAccount(object):
    def __init__(self, args):
        self.verbose = args.verbose
        # Load the config file
        self.settings = Settings(config_file=args.config_file,
                                 env=args.environment,
                                 verbose=self.verbose)
        # Set the basedn
        self.basedn = self.settings('ldap_basedn')
        # Set up the ldap connection
        self.ldap_conn()

    def ldap_conn(self):
        """
        Creates the LDAP connection based on the config file data.
        """
        # Connect to LDAP
        server = ldap3.Server(host=self.settings('ldap_server'), 
                              port=int(self.settings('ldap_port')))
        self.conn = ldap3.Connection(server, 
                        user=self.settings('ldap_user'),
                        password=self.settings('ldap_pw'),
                        auto_bind=False,
                        )
        try:
            # Enable TLS/Bind to LDAP
            if self.settings('ldap_tls'):
                self.conn.start_tls()
            self.conn.bind()
        except:
            print('\nUnable to reach LDAP server %s:%s.' % (self.settings('ldap_server'),
                                                          self.settings('ldap_port')))
            print('Please ensure your current IP has LDAP access.')
            sys.exit()
    
    def search(self, email, return_attrs=False):
        """
        Search the LDAP database for a specific email (mail attribute) and return the DN.
        Required for most LDAP commands.
        """
        # Run the search
        self.conn.search(search_base=self.basedn, 
                         search_filter='(&(objectClass=mailUser)(mail=%s))' % (email),
                         attributes=ldap3.ALL_ATTRIBUTES)
        # Ensure we have some results
        if self.conn.response == []:
            # No DN found
            sys.exit('\nEmail "%s" not found in LDAP database: %s.' % 
                        (email,self.settings('ldap_server') ))
        if return_attrs:
            for entry in self.conn.response:
                result = entry
            return result
        else:
            # Return the DN
            for entry in self.conn.response:
                # DNs are mail attr, so there shouldn't be multiple entries.
                dn = entry['dn']
            return dn          
        
    def unlock(self):
        """
        Unlocks an account without resetting the password.
        """
        # Prompt for required information
        prompts = {'mail': 'Email'}
        i = get_user_input(prompts)
        # Get the DN
        dn = self.search(i['mail'])
        # Remove the Lock
        c = self.conn.modify(dn, {'pwdAccountLockedTime': [(ldap3.MODIFY_DELETE, [])]})
        # Inform if account isn't locked.
        if self.conn.result['description'] == 'noSuchAttribute':
                print('\n%s not locked' % (i['mail']))
        # Output results with verbose on
        if self.verbose: 
            print('\n%s' % (self.conn.result))

    def lock(self):
        """
        Locks an email account, to prevent anyone from logging in. 
        Account will still get mail.
        """
        # Prompt for required information
        prompts = { 'mail': 'Email'}
        i = get_user_input(prompts)
        # Get the DN
        dn = self.search(i['mail'])
        # Set the timestamp
        dt = datetime.datetime.now(datetime.timezone.utc)
        # Lock the account
        c = self.conn.modify(dn, {'pwdAccountLockedTime': [(ldap3.MODIFY_ADD, [dt.strftime('%Y%m%d%H%M%SZ')])]})
        # Inform if account is already locked.
        if self.conn.result['description'] == 'constraintViolation':
                print('\n%s already locked' % (i['mail']))
        # Output results with verbose on
        if self.verbose:
            print('\n%s' % (self.conn.result))
    
    def list_locked(self):
        """
        List locked accounts.
        """
        # Run custom search, as it's a one off for now
        self.conn.search(search_base=self.basedn, 
                         search_filter='(&(objectClass=mailUser)(pwdAccountLockedTime=*))',
                         attributes=['pwdAccountLockedTime', 'mail'])
        # Show locked accounts/time
        if len(self.conn.response) > 0:
            print('\nLocked accounts: ')
            for entry in self.conn.response:
                print('- %s locked at %s' % (entry['attributes']['mail'][0],
                                            entry['attributes']['pwdAccountLockedTime']))
            print(' ')
        else:
            # Ensure the user knows when no locked account exist.
            print('\nNo locked accounts found.\n')
        # Output search results with verbose on
        if self.verbose:
            print(self.connf.response)

    def add_shadow(self):
        """
        Adds an email aliases (shadowAddress) to an email account.
        """
        # Prompt for required information
        prompts = {
                'mail': 'Email Address',
                'aliases': 'Aliases (comma separated)'
        }
        i = get_user_input(prompts)
        # Get the DN
        dn = self.search(i['mail'])
        # Turn aliases into a list of addresses
        i['shadow'] = i['aliases'].split(',')
        # Add the addresses to the account
        c = self.conn.modify(dn, {'shadowAddress': [(ldap3.MODIFY_ADD, i['shadow'])]})
        # Output results on failure or with verbose on
        if not c or self.verbose:
            print('\n%s' % (self.conn.result))
    
    def delete_shadow(self):
        """
        Adds an email aliases (shadowAddress) to an email account.
        """
        # Prompt for required information
        prompts = {
                'mail': 'Email Address',
                'aliases': 'Aliases'
        }
        i = get_user_input(prompts)
        # Get the DN
        dn = self.search(i['mail'])
        # Turn aliases into a list of addresses
        i['shadow'] = i['aliases'].split(',')
        # Delete the addresses from the account.
        c = self.conn.modify(dn, {'shadowAddress': [(ldap3.MODIFY_DELETE, i['shadow'])]})
        # Output results on failure or with verbose on
        if not c or self.verbose:
            print('\n%s' % (self.conn.result))
    
    def list_shadow(self):
        """
        List all aliases under an account
        """
        # Prompt for required information
        prompts = {
                'mail': 'Email Address',
        }
        i = get_user_input(prompts)
        # Search the account
        entry = self.search(i['mail'], return_attrs=True)
        # Output results
        print('\nAliases for %s: ' % (i['mail']))
        if len(entry['attributes']['shadowAddress']) == 0:
            print('None')
        else:
            for address in entry['attributes']['shadowAddress']:
                print(address)

    def add_account(self):
        """
        Create a new email account.
        """
        # Prompt for required information
        prompts = {
                'gn': 'Given Name',
                'sn': 'Surname',
                'mail': 'Email Address',
                'aliases': 'Aliases',
                'password': 'Password'
        }
        i = get_user_input(prompts)
        # Create all the variables we need for the new user
        i['uid'], i['domain'] = i['mail'].split('@')        
        i['mailbox'] = '/var/vmail/%s/%s' % (i['domain'], i['uid'])
        i['shadow'] = i['aliases'].split(',')
        i['password'] = hashed(ldap3.HASHED_SALTED_SHA, i['password'])
        # Add the account
        c = self.conn.add('mail=%s,ou=Users,domainName=%s,o=domains,%s' % 
                          (i['mail'], i['domain'], self.basedn),
                          ['inetOrgPerson', 'organizationalPerson',
                           'shadowAccount', 'top', 'mailUser', 'person'],
                          {'sn': i['sn'], 'givenName': i['gn'], 
                           'cn': '%s %s' % (i['gn'], i['sn']), 'uid': i['uid'],
                           'homeDirectory': i['mailbox'],
                           'userPassword': i['password'],
                           'shadowAddress': i['shadow']}
        )
        # Output results on failure or with verbose on
        if not c or self.verbose:
            print('\n%s' % (self.conn.result))
    
    def delete_account(self):
        """
        Delete an email account
        """
        # Prompt for required information
        prompts = {
                'mail': 'Email Address'
        }
        i = get_user_input(prompts)
        # Get the DN
        i['dn'] = self.search(i['mail'])
        # Delete the account
        c = self.conn.delete(i['dn'])
        # Output results on failure or with verbose on
        if not c or self.verbose:
            print('\n%s' % (self.conn.result))
    

def get_user_input(prompts):
    """
    Prompt user for information required for the various actions.
    Prompts is a dict of {key: value}.
    """
    print('')  # Aesthetics ;)
    # Create a dict to hold the results
    results = {}
    # Loop through the prompts
    for p in prompts:
        # Handle password prompts with getpass.
        if p == 'password':
            results[p] = getpass.getpass()
        else:
            results[p] = input('%s: ' % prompts[p])
    # Return collected results
    return results


def main():
    # Set up possible actions
    function_map = {'add_account': 'add_account',
                    'delete_account': 'delete_account',
                    'add_shadow': 'add_shadow',
                    'delete_shadow': 'delete_shadow',
                    'list_shadow': 'list_shadow',
                    'lock': 'lock',
                    'unlock': 'unlock',
                    'list_locked': 'list_locked'

    }
    # Create menu with argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Enable verbose output.', action='store_true')
    parser.add_argument('-c', '--config_file', default=config_file,
                        help='Path to configuration file. Default ~/.ldap.ini')
    parser.add_argument('-e', '--environment', 
                        default=None,
                        help='Specify the environment instead of being prompted when multiple defined in config file.')
    parser.add_argument('action', choices=function_map.keys(), help='LDAP action to perform.')
    parser.parse_args()
    args = parser.parse_args()
    
    # Run the function
    email = ManageAccount(args)
    action = getattr(ManageAccount, function_map[args.action])
    result = action(email)
    

main()
