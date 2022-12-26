import argparse
import configparser
import os.path
import datetime
import subprocess
import re
import json

class b2_summary(object):
    """
    Executes the b2 sync command and summarizes the output.
    """
    def __init__(self, args):
        """
        Set up our variables, load the config file.
        """
        self.verbose = args.verbose
        self.dry_run = args.dry_run
        self.config = self.load_config(args.config, args.src)
        self.list_sym = args.list_symlinks
        
    def __call__(self):
        """
        Run the b2 command, check and summarize output.
        """
        cmd_list = self.build_cmd()
        os_env = self.build_env()
        start = datetime.datetime.now()
        c = subprocess.run(cmd_list, env=os_env, capture_output=True)
        end = datetime.datetime.now()
        self.filter_results(c.stdout.decode("utf-8"), c.stderr.decode("utf-8"),
                            end - start)
              
    def load_config(self, config_file, src):
        """
        Load the config file.
        """
        if self.verbose:
            print('Loading config file "%s".' % config_file)
        config = configparser.ConfigParser()
        config.read(os.path.expanduser(config_file))
        return dict(config.items(src)+config.items('main')) 

    def build_cmd(self):
        """
        Build the b2 command string.
        """
        cmd = ['/usr/backblaze/bin/b2', "sync"]
        if self.dry_run:
            cmd.append('--dryRun')
        cmd.extend(['--destinationServerSideEncryption=SSE-C','--replaceNewer',
                    '--threads', self.config['threads'], 
                     '--keepDays', self.config['keep_days']])
        if self.config['ignore_dirs']:          
            for dir in json.loads(self.config['ignore_dirs']):
                cmd.extend(['--excludeDirRegex', dir])
        cmd.extend([self.config['src'], self.config['dest']])  
        if self.verbose:
            print(' '.join(cmd))
        return cmd
    
    def build_env(self):
        """
        Setup the environment variables.
        """
        b2_b64 = 'b2_destination_sse_c_key_b64'
        b2_id = 'b2_destination_sse_c_key_id'
        return dict(os.environ,
                    B2_DESTINATION_SSE_C_KEY_B64=self.config[b2_b64],
                    B2_DESTINATION_SSE_C_KEY_ID=self.config[b2_id])
    
    def filter_results(self, stdout, stderr, runtime): 
        """
        Filter the results, output summary.
        """      
        uploaded = re.findall('upload .+', stdout)
        hidden = re.findall('hide .+', stdout)
        symlinks = re.findall(r'WARNING: (.+\(broken symlink\?\))', stdout,)
        print('Runtime: %s' % (str(runtime).split(".")[0]))
        print('Uploaded: %s\nHidden: %s\n' % 
            (len(uploaded), len(hidden)))
        if self.list_sym:
            for bl in set(symlinks):
                print(bl)
        if self.verbose:
            print('STDOUT: %s\n' % (stdout))
        if self.verbose and stderr:
            print('STDERR: %s\n' % (stderr))
    
               
def main():
    # Create menu with argparse
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-v', '--verbose', help='Enable verbose output.', action='store_true')
    parser.add_argument('-t', '--dry-run', help='Simulate execution without making changes.', 
                        action='store_true')
    parser.add_argument('-c', '--config', help='Set custom path for configuration.', default='~/.b2.conf')
    parser.add_argument('-l', '--list-symlinks', help='Output the list of broken symlinks.', 
                        action='store_true', default=False)
    parser.add_argument('src', help='Source path for the backup job.')
    
    parser.parse_args()
    args = parser.parse_args()

    # Everything else
    sync = b2_summary(args)
    sync()


main()