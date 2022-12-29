# Variables

Included below is a list of variables with descriptions and examples for the various ansible roles. Variables that the user isn't expected to define are not included. See env/example/ for an example set of variables for the various plays.

## allow_reboot
Roles: none

When true, a host can be restarted when required during upgrades in the update.yml playbook.

Example:
```
allow_reboot: true
```

Default:
```
allow_reboot: false
```
---

## ansible_vault_password_file
Roles: dev

The path to the file containing the ansible vault password. 

Example:
```
ansible_vault_password_file: /usr/ansible/.vault
```

Default:
```
ansible_vault_password_file: '/home/{{ primary_user }}/.ssh/ansible'
```
---

## backblaze_app_id
Roles: backblaze

The app ID used by the host. Idenfities the server's ID/Key used to authenticate from backblaze_app_keys.

Example:
```
backblaze_app_id: cloud1
```

Default:
```
backblaze_app_id: '{{ inventory_hostname_short }}'
```
---

## backblaze_app_keys
Roles: backblaze

A dictionary of Backblaze App Key names, IDs and keys. App Keys can be created under Account --> App Keys.


Example:
```
backblaze_app_keys:
  cloud1:
    app_id: 0000000000000000000000001
    app_key: ABCDEFGEHJklmnopkrstuvwxyz1234567
  vm1:
    app_id: 0000000000000000000000002
    app_key: ABCDEFGEHJklmnopkrstuvwxyz1234568
```

Default:
```
backblaze_app_keys: {}
```


## backblaze_backups
Roles: backblaze

A list Backblaze backup jobs. Each list item is a dictionary of settings for the job and should include:
- name: The job name
- keep_days: Keep previous versions for this many days
- path: Path of the directory to backup.
- bucket: Bucket name/path

Example:
```
backblaze_backups:
  - name: email
    keep_days: 60
    path: /var/vmail
    bucket: email
```
Default:
```
backblaze_backups: []
```
---

## backblaze_config_dir
Roles: backblaze

The directory that will hold the SSE-C encryption ID/key information for the backup jobs.

Example:
```
backblaze_config_dir: /usr/backup
```

Default:
```
backblaze_config_dir: /root
```
---

## backblaze_default_hour
Roles: backblaze

Default hour of the day to run Backblaze cronjobs. Used if not otherwise defined for a backblaze_backup.

Example:
```
backblaze_default_hour: '23'
```

Default:
```
backblaze_default_hour: '04'
```
---

## backblaze_default_keepdays
Roles: backblaze

Default number of days to keep previous versions of backup files. Used if not otherwise defined for a backblaze_backup.

Example:
```
backblaze_default_keepdays: 60
```

Default:
```
backblaze_default_keepdays: 30
```
---

## backblaze_ssec_keys
Roles: backblaze

A dictionary of all SSE-C encryption keys and IDs for encrypting backups to Backblaze. Each set of keys is listed under their backblaze_app_id allowing us to store all ssec_keys in a single variable in the group secrets file.

You can use ```openssl rand -base64 32``` to generate the base64 encryption key. Key ID is a random string of A-Z, a-z, 0-9.

Example:
```
backblaze_ssec_keys:
  email:
    key_b64: QW4gZXhhbXBsZSBiYXNlNjQga2V5LiBQbGVhc2UgY2hhbmdlIGl0IQo=
    key_id: ABCDEFGHabcdefgh0123456789
  website:
    key_b64: QW5gZXhhbXBsZSBiYXNlNjQga2V5LiBQbGVhc2UgY2hhbmdlIGl0Ii6=
    key_id: BBCDEFGHabcdefgh0123456789
```

Default:
```
backblaze_ssec_keys: {}
```
---

## backblaze_venv
Roles: backblaze

The python virtual environment path for the Backblaze b2 package.

Example:
```
backblaze_venv: /usr/backup
```

Default
```
backblaze_venv: /usr/backblaze
```
---

## backup_dir
Roles: certbot_dns, common, dashy, dns, emby_server, kodi, ldap, mail, roundcube, wiki

The path to the local directory used for backing up data through ansible.

Example:
```
backup_dir: "/usr/backups/ansible"
```

Default:
```
backup_dir: "{{ playbook_dir }}/env/{{ env }}/backups"
```
---

## bash_colour:
Roles: common

Sets the bash prompt colour for the primary user.

Example:
```
bash_colour: 34
```

Default:
```
bash_colour: 36
```
---

## bind_ipv6: 
Roles: common, dns

IPv6 address used for Bind9. Use "false" to disabled IPv6.

Example: 
```
bind_ipv6: 2001:db8:c2ee::8
```

Default:
```
bind_ipv6: '{{ ipv6_address }}'
```
---

## cert_dns_server
Roles: certbot_dns

The IP address of the primary authoritative DNS server to run certbot against.

Example:
```
cert_dns_server: '172.16.1.8'
```

Default:
```
cert_dns_server: '{{ nameservers[nameservers | first].ipv4 }}'
```
---

## cert_domain
Roles: certbot

Primary hostname/domain used for a certbot certificate.

Example:  
```
cert_domain: example.local 
```

Default:   
```
#cert_domain:
```
---

## cert_domains
Roles: certbot_dns

A list of domains to generate wildcard certificates on.

Example:
```
certbot_domains:
    - example.com
    - example.net
    - example.local
```

Default:
```
cert_domains: '[{{ cert_name }}]'
```
---

## cert_email
Roles: certbot, certbot_dns

Email address to register Let's Encrypt certificate with during initial generation.

Example:
```
cert_email: admin@example.local
```

Default:
```
cert_email: 'certs@{{ cert_domain }}'
```
---

## cert_extra_domains
Roles: certbot

A list of additional domains used for the certbot certificate.

Example:
``` 
cert_extra_domains:  
    - www.example.local  
    - webmail.example.local  
```

Default:
```
cert_extra_domains: []
```
---

## cert_group
Roles: certbot, certbot_dns

Group used to provide other applications/users access to the certificates.  

Example:
```  
cert_group: ssl-certs
```

Default:
```
cert_group: ssl-certs
```
---

## cert_ipv6
Roles: certbot

IPv6 address to use for the certificate generation with certbot/Let's Encrypt. Default is all IPv6.

Example:
```  
cert_ipv6: '2001:db8:c2ee::1'
```

Default:
```
cert_ipv6: '[::]'   
```
---

## cert_name
Roles: cerbot_dns

The name to use for the certificate folder.

Example:
```
cert_name: www.example.local
```

Default:
```
#cert_name: example.com
```
---

## cert_scripts
Roles: certbot, certbot_dns

Scripts to be run whenever any certificate is renewed.

Example:
```
cert_scripts:  
    - python3.6 /root/pbx_cert.py pbx.example.local
```

Default:
```  
cert_scripts: []
```
---

## cert_services
Roles: certbot, certbot_dns

Services to restart whenever any certifcate is renewed.

Example:
```
cert_services:  
    - nginx  
    - slapd  
    - dovecot  
    - postfix  
```

Default:
```  
cert_services: [nginx]
```
---

## certbot_dns_enable
Roles: dns

Allows wildcard certbot_dns to be run against the master authoritative server when enabled. 

Example:
```
certbot_dns_enable: false
```

Default:
```
certbot_dns_enable: true
```
---

## composer_version
Roles: roundcube

Compare installed version of composer against this variable. Install latest version of composer if the values don't match.

Example:
```
composer_version: 2.4.0
```

Default:
```
composer_version: 2.5.1
```
---

## core_apps
Roles: common

A list of apps to install on all systems, or at least all the ones running the common role.

Example:
```
core_apps:  
    - sudo  
    - p7zip  
    - nano  
    - wget  
```

Default:
```
core_apps: [sudo, p7zip, unzip, nano, rsync, tmux, wget, curl, dnsutils]
```
---

## cron_email
Roles: common

Set the mailto address for crontab to this email address, when define.

Example:
```
cron_email: cron@example.local
```

Default:
```
cron_email: false
```
---

## dashy_cert_name
Roles: dashy

The name to use for the dashy certificate folder generated by Let's Encrypt.

Example:
```
dashy_cert_name: example.local
```

Default:
```
dashy_cert_name: '{{ dashy_hostnames | first }}'
```
---


## dashy_hostnames
Roles: dashy

A list of hostnames that can be used for accessing dashy.

Example:
```
dashy_hostnames:
  - dashy.example.local
  - home.example.local
```

Default:
```
dashy_hostnames:
  - 'dashy.{{ default_domain }}'
```
---

## dashy_ipv6:
Roles: dashy

The IPv6 address used for dashy.

Example:
```
dashy_ipv6: 2001:db8:c2ee:da54:1
```

Default:
```
dashy_ipv6: false
```
---

## dashy_name
Roles: dashy

The title/name of the dashy website.

Example:
```
dashy_name: 'Example Dashy'
```

Default:
```
dashy_name: 'Dashy'
```
---

## dashy_style
Roles: dashy

The style/theme used by dashy by default.

Example:
```
dashy_style: callisto
```

Default:
```
dashy_style: one-dark
```
---

## dashy_users
Roles: dashy

A dictionary containing usernames and their passwords for access to dashy. 

Example:
```
dashy_users:
  admin:
    password: "$ecretPassw0rd."
  dashy:
    password: "dashy"
```

Defaut:
```
dashy_users: {}
```
---

## default_editor
Roles: common

Sets the default editor for the primary_user.

Example:
```
default_editor: vim
```

Default:
```
default_editor: nano
```
---

## default_domain
Roles: dashy, dns

The main/default domain to used for some default role variables. Setting this allows you to leave several other variables unset.

Example:
```
default_domain: example.local
```

Default:
```
# default_domain: ""
```
---

## dev_pkgs
Roles: dev

A list of packages to be installed on developer VMs.

Example:
```
dev_pkgs: 
  - code
  - ansible
  - github
  - python3-venv
```

Default:
```
dev_pkgs: [chromium, thunderbird, jxplorer, code, ansible,
           git, whois, python3-passlib, python3-venv, cifs-utils,
           sshfs]
```
---

## dkim_key
Roles: dns, mail

The current DKIM key being used by the mail servers.

Example:
```
dkim_key: '2203'
```

Default:
```
dkim_key: 'dkim'
```
---

## dkim_keys
Roles: dns, mail

A list of still valid DKIM keys still allowed by the mail servers.

Example:
```
dkim_keys
  - 2202
  - {{ dkim_key }}
```

Default:
```
dkim_keys: ['{{ dkim_key }}']
```
---

## dkim_txt_dir
Roles: dns

The directory containing the DKIM text records for the bind9 authoriative DNS server.

Example:
```
dkim_txt_dir: /etc/bind/dkim
```

Default:
```
dkim_txt_dir: /var/lib/bind/dkim
```
---

## dmarc_default_txt
Roles: dns

The default DMARC text record used when a DNS zone doesn't have one explicitly defined. See https://www.zytrax.com/books/dns/ch9/dmarc.html for more information.

Example:
```
dmarc_default_txt: "v=DMARC1;p=none;sp=reject;pct=10;rua=mailto:dmarc@example.local"
```

Default:
```
dmarc_default_txt: "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s;fo=1;rf=afrf;rua=mailto:dmarc@{{ domain }}"
```
>Note: Default example uses "domain" variable, which turns into the current domain during the play. For example, if the zone is example.local, {{ domain }} becomes example.local. 
---

## dns_forwarders
Roles: pihole

DNS resolvers to forward pihole DNS queries to when address not in local_dns_zones and not an ad. Typically your ISP or a public one: https://en.wikipedia.org/wiki/Public_recursive_name_server.

Example:
```
dns_forwarders:
  - 2001:4860:4860:0:0:0:0:8888
  - 2001:4860:4860:0:0:0:0:8844
  - 2606:4700:4700::1111
  - 2606:4700:4700::1001
  - 1.1.1.1
  - 1.0.0.1
  - 8.8.8.8
  - 8.8.4.4
  - 4.2.2.1
  - 4.2.2.2
```

Default:
```
dns_forwarders: ['8.8.8.8', '4.4.4.4']
```
---

## dns_resolvers
Roles: common

A list of resolver/recursive nameservers to use on a system. You can enter both IPv4 & IPv6 addresses. If unset, the resolvers on the host are not modified.

Example: 
```
dns_resolvers:
  - 8.8.8.8
  - 8.8.4.4
  - 2001:4860:4860::8888
  - 2001:4860:4860::8844
```

Default:
```
dns_resolvers: []
```
---

## dns_zone_expire
Roles: dns

The time in seconds before the secondary servers stop serving zone data when unable to refresh the data from the primary server.

Example:
```
dns_zone_expire: 648000
```

Default:
```
dns_zone_expire: 1209600
```
---

## dns_zone_refresh
Roles: dns

The time in seconds a secondary server will ask the primary server for updates on a zone record.

Example:
```
dns_zone_refresh: 14400
```

Default:
```
dns_zone_refresh: 7200
```
---

## dns_zone_retry
Roles: dns

The time in seconds before a secondary server retries a zone update from the primary server after failing a refresh.

Example:
```
dns_zone_retry: 1800
```

Default:
```
dns_zone_retry: 3600
```
---

## dns_zone_ttl
Roles: dns

The time in seconds that the record may be cached by any resolver.

Example:
```
dns_zone_ttl: 28800
```

Default:
```
dns_zone_ttl: 7200
```
---

## dns_zones
Roles: dns, site_placeholder

A dictionary containing the DNS information used for the authoritative zones. This includes IPv4 (A), IPv6 (AAAA), mail (MX) and aliases (CNAME) records. 

Example:
```
ns_zones:
  example.local:
    mail: mail.example.local
    backup_mail:
      - mail.example2.local
    dnssec: false
    spf_txt: 'v=spf1 a mx ~all'
    dmarc_txt: 'v=DMARC1;p=reject;adkim=s;aspf=s;fo=1;rf=afrf;rua=mailto:dmarc@example.local'
    hostnames:
      '@':
        ipv4: 192.168.0.2
        ipv6: 2001:db8:4321::1
      ip:
        ipv4: 192.168.0.2
        ipv6: 2001:db8:1234::1122
      ipv4:
        ipv4: 192.168.0.2
      ipv6: 
        ipv6: 2001:db8:1234::1122
      mail:
        ipv4: 192.168.0.2
        ipv6: 2001:db8:1234::3
      rspamd:
        ipv4: 192.168.0.2
        ipv6: 2001:db8:1234::4
      ldap:
        ipv4: 192.168.0.2
        ipv6: 2001:db8:1234::5
      cloud1:
        ipv4: 192.168.0.2
        ipv6: 2001:db8:1234::1
      cloud2:
        ipv4: 192.168.0.3
        ipv6: 2001:db8:4321::1
     cnames:
      autoconfig: 'mail.example.local'
      autodiscover: 'mail.example.local'
  example2.local:
    mail: mail.example.local
    backup_mail:
      - mail.example2.local
    dnssec: true
    hostnames: 
      '@':
        ipv4: 192.168.0.3
        ipv6: 2001:db8:4321::1
      mail:
        ipv4: 192.168.0.3
        ipv6: 2001:db8:4321::3
      emby:
        ipv6: 2001:db8:abcd::eb
        ipv4: 192.168.0.4
```

Default:
```
dns_zones: {}
```
---

## dnssec_algorithm_ids
Roles: dns

A dictionary of DNSSEC types and their IDs. Used to ensure DNSSEC keys exist for the algorithms in use.

Example:
```
dnssec_algorithm_ids: {NSEC3RSASHA1: 7, RSASHA256: 8, ECDSAP256SHA256: 13, ECDSAP384SHA384: 14, ED25519: 15, ED448: 16}
```

Default:
```
dnssec_algorithm_ids: {NSEC3RSASHA1: 7, RSASHA256: 8, ECDSAP256SHA256: 13, ECDSAP384SHA384: 14, ED25519: 15, ED448: 16}
```
---

## dnssec_algorithms
Roles: dns

A list of DNSSEC algorithms to generate keys for when DNSSEC is enabled on a zone.

Example:
```
dnssec_algorithms: [ECDSAP256SHA256, ECDSAP384SHA384]
```

Default:
```
dnssec_algorithms: [NSEC3RSASHA1, ECDSAP256SHA256, ECDSAP384SHA384]
```
---

## dnssec_bytes
Roles: dns

Key size in bytes used for generating new DNSSEC keys.

Example:
```
dnssec_bytes: 4096
```

Default:
```
dnssec_bytes: 2048
```
---

## doveadm_allow_list
Roles: common

A list of trusted hosts which will be allowed to access the Dovecot admin port, used for mail replication. Current configuration expects a list of inventory hostnames within the current environment, as we need to allow the IPs through the firewall but have it set to use the hostname for tcps. 

Example: 
```
doveadm_allow_list:
  - mail1.example.com
  - mail2.example.com
```

Default:
```
doveadm_allow_list: []
```
---

## doveadm_password
Roles: common, mail

Password used for doveadm, used for mail replication. Setting a password enables dovecot replication.

Example: 
```
doveadm_passwd: D0v3C0t
```

Default:
```
doveadm_passwd: false
```
---

## doveadm_port
Roles: common, mail

Port used for doveadm, which is used for mail replication.

Example: 
```
doveadm_port: 8045
```

Default:
```
doveadm_port: 12345
```
---

## dqs_key
Roles: mail

Your [SPAMHAUS](https://www.spamhaus.com) data query service key. A free account can be registered here: https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/. 

Example:
```
dqs_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Default:
```
dqs_key: false
```

## emby_allow_list
Roles: common

A list of trusted IPs/subnets (IPv4 & IPv6) which will be allowed to access the Emby Server.

Example: 
```
emby_allow_list:
  - 2001:db8:f2c:1234::/56
  - 192.168.1.0/24
  - 10.0.100.5
```

Default:
```
emby_allow_list: []
```
---

## emby_server_backup_dir
Roles: emby_server

The directory on the Emby Server used by the backup plugin.

Example:
```
emby_server_backup_dir: /local/backups/emby
```

Default:
```
emby_server_backup_dir: /usr/backups/emby
```
---

## emby_server_cert_name
Roles: emby_server

The name used for the Emby Server certbot certificate.

Example:
```
emby_server_cert_name: 'example.local'
```

Default:
```
emby_server_cert_name: '{{ emby_server_hostnames | first }}'
```
---

## emby_server_deb_url
Roles: emby_server

URL for the .deb file used to install Emby Server.

Example:
```
emby_server_deb_url: https://github.com/MediaBrowser/Emby.Releases/releases/download/4.6.6.0/emby-server-deb_4.6.6.0_amd64.deb
```

Default:
```
emby_server_deb_url: 'https://github.com/MediaBrowser/Emby.Releases/releases/download/{{ emby_server_version }}/emby-server-deb_{{ emby_server_version }}_amd64.deb'
```
---

## emby_server_hostnames
Roles: emby_server

A list of hostnames used for the Emby Server.

Example:
```
emby_server_hostnames: 
    - 'emby.example.local'
    - 'media.example.local'
```

Default:
```
emby_server_hostnames: 
    - 'emby.{{ default_domain }}'
```
---

## emby_server_plugin_backups
Roles: emby_server

When true, ansible will ensure the folder exists for the backups generated by the emby server plugin "Server Configuration Backup" and fetch a copy when the backups tasks are run.

Example:
```
emby_server_plugin_backups: true
```

Default:
```
emby_server_plugin_backups: false
```
---

## emby_theater_deb_url
Roles: emby_theater

The download URL for the emby theater deb file.

Example:
```
emby_theater_deb_url: 'https://github.com/MediaBrowser/emby-theater-electron/releases/download/3.0.19/emby-theater-deb_3.0.19_arm64.deb'
```

Default:
```
emby_theater_deb_url: 'https://github.com/MediaBrowser/emby-theater-electron/releases/download/{{ emby_theater_version }}/emby-theater-deb_{{ emby_theater_version }}_amd64.deb'
```
---

## emby_theater_user
Roles: emby_theater

The user running emby theater. Used to set Mate auto login user and emby theater launch on login.

Example:
```
emby_theater_user: emby
```

Default:
```
emby_theater_user: media
```
---

## emby_theater_version
Roles: emby_theater

Sets the version of emby theater to install on the host.

Example:
```
emby_theater_version: 3.0.18
```

Default:
```
emby_theater_version: 3.0.19
```
---

## emby_server_version
Roles: emby_server

Sets the version of the emby server you wish installed on the system. 

Example:
```
emby_server_version: 4.7.10.0
```

Default:
```
emby_server_version: 4.7.11.0
```

## files_admin_password
Roles: files

The password used to access the files/Jirafeau admin panel at <site>/admin.php.

Example:
```
files_admin_password: A_Secure_Password
```

Default:
```
#files_admin_password: ''
```
---

## files_cert_name
Roles: files

The name used for the files/Jirafeau certbot certificate.

Example:
```
files_cert_name: 'example.local'
```

Default:
```
files_cert_name: '{{ files_hostnames | first }}'
```
---

## files_company
Roles: files

The company name to brand the files/Jirafeau site with.

Example:
```
files_company: 'Acme Inc.'
```

Default:
```
files_company: Jirafeau
```
---

## files_contact
Roles: files

The contact name and email address for abuse reports from the files/Jirafeau site.

Example:
```
files_contact: 'Abuse <abuse@example.local>'
```

Default:
```
files_contact: 'Abuse <abuse@{{ default_domain }}>'
```
---

## files_crypt_enable
Roles: files

When true, it enables server side encryption using AES256. This increases the load on the server and disables de-duplication.

Example:
```
files_crypt_enable: true
```

Default:
```
files_crypt_enable: false
```
---

## files_hostnames
Roles: files

A list of hostnames that can be used to access the files/Jirafeau site.

Example:
```
files_hostnames:
    - 'files.example.local'
    - 'upload.example.local'
```

Default:
```
files_hostnames:
    - 'files.{{ default_domain}}'
```
---

## files_ipv6
Roles: files

The IPv6 address used for the files/Jirafeau site. Disabled when set to false.

Example:
```
files_ipv6: 2001:db8:4321::6
```

Default:
```
files_ipv6: false
```
---

## files_root
Roles: files

The root directory for the files/Jirafeau site.

Example:
```
files_root: '/var/www/files.example.local'
```

Default:
```
files_root: '/var/www/files'
```
---

## files_style
Roles: files

Theme to use for the files/Jirafeau site.

Example:
```
files_style: 'modern'
```

Default:
```
files_style: 'dark-courgette'
```
---

## files_title
Roles: files

The title of the files/Jirafeau site.

Example:
```
files_title: Example Uploads
```

Default:
```
files_title: File Transfer
```
---

## files_upload_allow_ips
Roles: files

When set, only allow file uploads from these IPs. CIDR notation is available for IPv4 only.

Example:
```
files_upload_allow_ips:
  - 192.168.1.0/24
  - 2001:db8:4321::6
  - 10.0.0.2
```

Default:
```
files_upload_allow_ips: []
```
---

## files_upload_passwordless_ips: []
Roles: files

A list of IPs that can upload files without supplying one of the files_upload_passwords. This variable does nothing if the files_upload_passwords varible isn't set. CIDR notation is available for IPv4 only

Example:
```
files_upload_passwordless_ips:
  - 192.168.1.0/24
  - 2001:db8:4321::6
  - 10.0.0.2
```

Default:
```
files_upload_passwordless_ips: []
```
---

## files_upload_passwords
Roles: files

When set, this is a list of upload passwords required to upload files to the files/Jirafeau site when not connecting from an IP listed in files_upload_passwordless_ips. 

Example:
```
files_upload_passwords:
  - Jirafeau
  - LetMeIn
  - UploadNow
```

Default:
```
files_upload_passwords: []
```
---

## files_var
Roles: files

The folder used to store the uploaded files. A random sequence will be generated automatically if the variable is not set.

Example:
```
files_var: 'var-HL6NveQ3ZHpstGn'
```

Default:
```
files_var: ''
```
---

## firewall_enable
Roles: common

OS specific firewall will be enabled if true. Hosts in a group named "public" automatically have this variable set to true.

Example:
```
firewall_enable: true
```

Default:
```
firewall_enable: false
```
---

## firewall_open_ports
Roles: common

A list of ports you wish to allow through iptables. False to disable.

Example:
```
firewall_open_ports: 
  4379:
    udp: true
  27015:
    tcp: true
    udp: true
```

Default:
```
fw_custom: false
```
---

## force_ipv4_mounts
Roles: emby_server, kodi, transmission

Force SMB mounts to use IPv4 instead of hostnames. Required local_dns_zones to be set.

Example:
```
force_ipv4_mounts: true
```

Default:
```
force_ipv4_mounts: false
```
---

## guest_additions_path
Roles: vboxguest

Path to the guest additions installer.

Example:
```
guest_additions_path: /mnt/cdrom/VBoxLinuxAdditions.run
```

Default:
```
guest_additions_path: /media/cdrom/VBoxLinuxAdditions.run
```
---

## guest_addition_pkgs
Roles: vboxguest

A list of packages required for building the virtualbox guest additions.

Example:
```
guest_addition_pkgs:
  - build-essential
  - dkms
  - 'linux-headers-{{ ansible_kernel }}'
```

Default:
```
guest_addition_pkgs:
  - build-essential
  - dkms
  - 'linux-headers-{{ ansible_kernel }}'
```
---

## ip_check_url
Roles: transmission

Website used to check your public IP address. Tested with site_ip role's IPv4 check.

Example:
```
ip_check_url: ipv4.example.com
```

Default:
```
ip_check_url: ifconfig.me
```
---

## ipv6_address
Roles: common

Primary IPv6 address on the host. Use "false" to disable IPv6.

Example: 
```
ipv6_address: 2001:db8:c2ee::2
```

Default:
```
ipv6_address: false
```
---

## ipv6_addresses
Roles: common

A list of any IPv6 addresses you want ansible to configure on the host.

Example: 
```
ipv6_addresses:
  - 2001:db8:c2ee::1
  - 2001:db8:c2ee::2
  - '{{ bind_ipv6 }}'
  - 2001:db8:c2ee::4
  - 2001:db8:c2ee::a1
  - 2001:db8:c2ee::a2
  - 2001:db8:c2ee::a3
```

Default:
```
ipv6_addresses: []
```
---

## kodi_audio_device
Roles: kodi

The audio device used for Kodi. This variable has to be set on the host using the GUI, then copied into the variable from the config file.

Example:
```
kodi_audio_device: "ALSA:hdmi:CARD=vc4hdmi,DEV=0"
```

Default:
```
kodi_audio_device: ALSA:default
```
---

## kodi_audio_passthrough
Roles: kodi

When true, passthrough mode (raw audio stream) is enable for kodi audio. See the Kodi Wiki for more information: https://kodi.wiki/view/Settings/System/Audio.

Example:
```
kodi_audio_passthrough: false
```

Example:
```
kodi_audio_passthrough: true
```
---

## kodi_hostname
Roles: kodi

The hostname used for accessing Kodi.

Example:
```
kodi_hostname: kodi.example.local
```

Default:
```
kodi_hostname: '{{ inventory_hostname }}'
```
---

## kodi_resolution_id
Roles: kodi

Kodi resolution ID. Default is set for 1920x1080. Another value that must be set through the GUI and pulled from the config file into ansible.

Example:
```
kodi_resolution_id: 20
```

Default:
```
kodi_resolution_id: 14
```
---

## kodi_screenmode
Roles: kodi

Kodi resolution/screen settings. Default is set for 1920x1080. Another value that must be set through the GUI and pulled from the config file into ansible.

Example:
```
kodi_screenmode: 0128000720060.00000pstd
```

Default:
```
kodi_screenmode: 0192001080060.00000pstd
```
---

## kodi_user
Roles: kodi

Kodi will be launched automatically when this user logs in.

Example:
```
kodi_user: media
```

Default:
```
kodi_user: pi
```
---

## kodi_web_port
Roles: kodi

The port used for the web remote for Kodi.

Example:
```
kodi_web_port: 80
```

Default:
```
kodi_web_port: 8088
```
---

## kodi_web_password
Roles: kodi

The password used for accessing the web remote.

Example:
```
kodi_web_password: kodi
```

Default:
```
kodi_web_password: '{{ inventory_hostname_short }}'
```
---

## kodi_web_user
Roles: kodi

The user used for accessing the web remote.

Example:
```
kodi_web_user: kodi
```

Default:
```
kodi_web_user: admin
```
---

## ldap_admin
Roles: ldap, mail, roundcube

The LDAP admin user's DN.

Example:
```
ldap_admin: "cn=admin,dc=example,dc=local"
```

Default:
```
ldap_admin: "cn=admin,{{ ldap_suffix }}"
```
---

## ldap_allow_list
Roles: common

A list of trusted IPs/subnets (IPv4 & IPv6) which will be allowed to access LDAP ports.

Example: 
```
ldap_allow_list:
  - 2001:db8:f2c:1234::/56
  - 192.168.1.0/24
  - 10.0.100.5
```

Default:
```
ldap_allow_list: []
```
---

## ldap_domain
Roles: ldap

Domain used to create the ldap_suffix variable default. 

Example:
```
ldap_domain: example.local
```

Default:
```
ldap_domain: "{{ default_domain }}"
```
---

## ldap_hostname
Roles: ldap

The hostname used for the LDAP server.

Example:
```
ldap_hostname: ldap.example.local
```

Default:
```
ldap_hostname: "{{ inventory_hostname }}"
```
---

## ldap_ipv6
Roles: common, ldap

IPv6 address used for LDAP. Use "false" to disabled IPv6.

Example: 
```
ldap_ipv6: 2001:db8:c2ee::4
```

Default:
```
ldap_ipv6: '{{ ipv6_address }}'
```
---

## ldap_localip
Roles: ldap

The internal IP address used for accessing LDAP. This is used for services accessing the LDAP database on the same host.

Example:
```
ldap_localip: 127.0.1.1
```

Default:
```
ldap_localip: 127.0.0.2
```
---

## ldap_log_level
Roles: ldap

Controls the log level on the LDAP server. See https://www.openldap.org/doc/admin24/slapdconfig.html for values.

Example:
```
ldap_log_level: 0x8 0x128 0x256
```

Default:
```
ldap_log_level: 0x64 0x8
```
---

## ldap_port
Roles: roundcube

Port used for LDAP connections.

Example:
```
ldap_port: 389
```

Default:
```
ldap_port: 636
```
---

## ldap_ppolicy_enable
Roles: ldap

When true, the LDAP password policy module is enabled. See https://www.zytrax.com/books/ldap/ch6/ppolicy.html for more details and for information the ppolicy module variables ppolicy_* and pwd*. See https://github.com/ltb-project/openldap-ppolicy-check-password for information on the check password variables pp_*.

Example:
```
ldap_ppolicy_enable: false
```

Default:
```
ldap_ppolicy_enable: true
```

## ldap_pw
Roles: ldap, mail, roundcube

The password for the LDAP admin user/DN.

Example:
```
ldap_pw: '$ecretPassw0rd.'
```

Default:
```
#ldap_pw: ''
```
---

## ldap_replication_enable
Roles: ldap

Enables ldap database replication when true.

Example: 
```
ldap_replication_enable: true
```

Default:
```
ldap_replication_enable: false
```
---

## ldap_replication_hosts
Roles: common, ldap

A dictionary of ldap replication hosts, and their IDs.

Example:
```
ldap_replication_hosts:
  ldap.example.local:
    id: 1
  ldap.example2.local:
    id: 2
```

Default:
```
ldap_replication_hosts: []
```
---

## ldap_replication_pw
Roles: ldap

The password for the LDAP replication user.

Example:
```
ldap_replication_pw: '$ecretPassw0rd.'
```

Default:
```
#ldap_repliation_pw: ''
```
---

## ldap_replication_scheme
Roles: ldap

The protocol used for replication connections between the LDAP servers. Either ldap or ldaps.

Example:
```
ldap_replication_scheme: ldap
```

Default:
```
ldap_replication_scheme: ldaps
```
---

## ldap_replication_user
Roles: ldap

User DN used for replicating the LDAP database.

Example:
```
ldap_replication_user: "cn=replicator,dc=example,dc=local"
```

Default:
```
ldap_replication_user: "cn=replicator,{{ ldap_suffix }}"
```
---

## ldap_rootdn
Roles: ldap

The LDAP root user's DN.

Example:
```
ldap_rootdn: "cn=root,dc=example,dc=local"
```

Default:
```
ldap_rootdn: "cn=root,{{ ldap_suffix }}"
```
---

## ldap_rootpw
Roles: ldap

Thhe password for the LDAP root user/DN.

Example:
```
ldap_rootpw: '$ecretPassw0rd.'
```

Default:
```
#ldap_rootpw: ''
```
---

## ldap_scheme
Roles: ldap, mail, roundcube

The protocol used for connections to the LDAP server. ldap, ldaps or ldapi.

Example:
```
ldap_scheme: ldaps
```

Default:
```
ldap_scheme: ldapi
```
---

## ldap_server
Roles: ldap, mail, roundcube

The hostname/server to use for LDAP connections.

Example:
```
ldap_server: ldap.example.local
```

Default:
```
ldap_server: '%2Fvar%2Frun%2Fldapi'
```
---

## ldap_suffix
Roles: ldap, mail, roundcube

The LDAP suffix/root. The topmost entry in the LDAP database.

Example:
```
ldap_suffix: dc=example,dc=local
```

Default:
```
ldap_suffix: "{{ 'dc={0},dc={1}'.format(*ldap_domain.split('.')) }}"
```
---

## ldap_tls
Roles: mail, roundcube

When true, use TLS when connecting to LDAP server.

Example:
```
ldap_tls: true
```

Default:
```
ldap_tls: false
```
---

## local_dns_zones
Roles: emby_server, kodi, pihole, transmission

A dictionary defining the local DNS zone hosts and IPv4s.

Example:
```
local_dns_zones:
  example.local:
    pbx: 192.168.0.
    vm1: 192.168.0.4
    vm2: 192.168.0.5
    nas: 192.168.0.10
    torrents: 192.168.0.4
    dashy: 192.168.0.4
    emby: 192.168.0.4
    rpi1: 192.168.0.20
  example2.local:
    nas: 192.168.0.10
    torrents: 192.168.0.4
    dashy: 192.168.0.4
    dashy: 192.168.0.4
    emby: 192.168.0.4
    rpi1: 192.168.0.20
```

Default:
```
local_dns_zones: {}
```
---

## local_subnet
Roles: common 

The local IPv4 subnet/network for the host.

Example:
```
local_subnet: `192.168.0.0/24`
```

Default:
```
local_subnet: '127.0.0.0/24'
```
---

## local_subnets
Roles: emby_server, kodi

A list of local subnets for the host.

Example:
```
local_subnets: 
    - 192.168.1.0/24  # Main
    - 192.168.2.0/24  # Wireless
```

Default:
```
local_subnets: ['{{ local_subnet }}']
```
---

## mail_domains
Roles: dns, ldap, mail

A list of domains that will be allowed to send/receive mail.

Example:
```
mail_domains:
  - example.local
  - example2.local
```

Default:
```
mail_domains: []
```
---

## mail_hostname
Roles: mail

The hostname for the mail server. 

Example:
```
mail_hostname: mail.example.local
```

Default:
```
mail_hostname: "mail.{{ primary_mail_domain }}"
```
---

## mail_ipv6
Roles: common, mail

IPv6 address used for mail services. Use "false" to disabled IPv6.

Example: 
```
mail_ipv6: 2001:db8:c2ee::3
```

Default:
```
mail_ipv6: '{{ ipv6_address }}'
```
---

## mail_localip
Roles: mail

Local IP address to use for local mail services.

Example:
```
mail_localip: 127.0.0.1
```

Default:
```
mail_localip: 127.0.0.3
```
---

## mail_server
Roles: roundcube, sendmail, monit

The hostname of the mail server to send our mail from.

Example:
```
mail_server: mail.example.local
```

Default:
```
mail_server: 'mail.{{ default_domain }}'
```
---

## mail_users
Roles: ldap

A dictionary of mail users to add when seeding the LDAP database.

Example:
```
mail_users:
  admin:
    domain: example.local
    name: Admin User
    password: '$ecretPassw0rd.'
  notify:
    domain: example.local
    name: Notification Email
    password: 'N0t1fyM3!'
```

Default:
```
mail_users: {}
```
---

## message_size_limit
Roles: mail

The maximum file size (in bytes) for emails including attachments the server will allow. 

Example:
```
message_size_limit: 10000000
```

Default:
```
message_size_limit: 20480000
```
---

## monit_email
Roles: monit

Set the email address that will be receiving the alert emails from monit.

Example:
```
monit_email: monit@example.com
```

Default:
```
monit_email: 'monit@{{ default_domain }}'
```
---

## monit_email_port
Roles: monit

Set the email port to use for monit alerts.

Example:
```
monit_email_port: 25
```

Default:
```
monit_email_port: 587
```
---

## monit_enabled
Roles: common, dns, emby_server, emby_theater, ldap, mail, nginx, samba, transmission, wireguard

When true, monit will be installed and configured for the various roles.

Example:
```
monit_enabled: false
```

Default:
```
monit_enabled: true
```
---

## nameservers
Roles: dns

A dictionary containing the name, domain and IPs for the authoritative DNS servers.

Example:
```
nameservers:
  ns1:
    ipv4: 192.168.0.2
    ipv6: 2001:db8:1234::2
    domain: example.local
  ns2:
    ipv4: 192.168.0.3
    ipv6: 2001:db8:4321::2
    domain: example.local
```

Default:
```
nameservers: {}
```
---

## node_version
Roles: nodejs

The version of nodejs to install on the host.

Example:
```
node_version: 14
```

Default:
```
node_version: 16
```
---

## node_gpg_id
Roles: nodejs

The ID of the gpg signing key to download from NodeSource for the repository. See https://github.com/nodesource/distributions/blob/master/README.md

Example:
```
node_gpg_id: 9FD3B784BC1C6FC31A8A0A1C1655A0AB68576280
```

Default:
```
node_gpg_id: 9FD3B784BC1C6FC31A8A0A1C1655A0AB68576280
```
---

## ns_domain
Roles: dns

The domain used for the authoritative DNS servers. 

Example:
```
ns_domain: example.local
```

Default:
```
ns_domain: '{{ default_domain }}' 
```
---

## os_gui
Roles: kodi

Used for restarting Kodi by restarting the active session.

Example:
```
os_gui: gdm
```

Default:
```
os_gui: lightdm
```
---

## pbx_cert_name
Roles: pbx

The name used for the PBX certbot certificate.

Example:
```
pbx_cert_name: example.local
```

Default:
```
pbx_cert_name: ['{{ pbx_cert_name | first }}']
```
---

## pbx_hostnames:
roles: pbx

The hostnames used for the PBX server.

Example:
```
pbx_hostnames:
  - pbx.example.local
  - '{{ inventory_hostname }}
```

Default:
```
pbx_hostnames: 
  - 'pbx.{{ default_domain }}'
```
---

## php_fpm
Roles: roundcube

Name of the php-fpm command used on the system.

Example:
```
php_fpm: 'php7.4-fpm'
```

Default:
```
php_fpm: '{{ php_version }}-fpm'
```
---

## php_version
Roles: roundcube

Version of PHP used on the system. Used for the default php_fpm variable and for installing php modules.

Example:
```
php_version: php7.3
```

Default:
```
php_version: php7.4
```
---

## pihole_cert_domains
Roles: pihole

A list of domains to include with the wildcard certificate for pihole.

Example:
```
pihole_cert_domains: 
  - example.local
  - example2.local
```

Default:
```
pihole_cert_domains: []
```
---

## pihole_cert_name
Roles: pihole

The name of the certbot certificate used for the pihole services.

Example:
```
pihole_cert_name: 'example.local'
```

Default:
```
pihole_cert_name: '{{ pihole_hostname}}'
```
---

## pihole_dnssec
Roles: pihole

When true, pihole will attempt to use DNSSEC to validate the DNS response. 

Example:
```
pihole_dnssec: false
```

Default:
```
pihole_dnssec: false
```
---

## pihole_domain_exceptions
Roles: pihole

A list of domains to remove from the downloaded ad block lists.

Example:
```
pihole_domain_exceptions:
  - ads.example.local
  - cdn.example.local
```

Default:
```
pihole_domain_exceptions: []
```
---

## pihole_hostname
Roles: pihole

The hostname used to access the pihole dashboard.

Example:
```
pihole_hostname: "pihole1.example.local"
```

Default:
```
pihole_hostname: "{{ inventory_hostname }}"
```
---

## pihole_https_enable
Roles: pihole

When true, the pihole dashboard will be set up over HTTPS using certbot to generate a wildcard certificate for the hostname domain.

Example:
```
pihole_https_enable: false
```

Default:
```
pihole_https_enable: true
```

## pihole_ipv6
Roles: pihole

IPv6 address used for the pihole and the pihole dashboard.

Example:
```
pihole_ipv6: "2001:db8:4444::7"
```

Default
```
pihole_ipv6: "{{ ipv6_address | default(false) }}"
```
---

## pihole_password
Roles: pihole

The password to login into the admin section of the pihole dashboard.

Example:
```
pihole_password: '$ecretPassw0rd.'
```

Default:
```
pihole_password: pihole
```

## postgresql_root_password
Roles: roundcube

The root password for the postgresql installation.

Example:
```
postgresql_root_password: '$ecretPassw0rd.'
```

Default:
```
#postgresql_root_password: ''
```

## postgresql_version:
Roles: roundcube

The version of postgresql to install.

Example:
```
postgresql_version: 12
```

Default:
```
postgresql_version: 13
```
---

## primary_mail_domain
Roles: mail

Domain used to create some default mail variables and for creating the root, null and do-not-reply virtual addresses.

Example:
```
primary_mail_domain: example.local
```

Default:
```
primary_mail_domain: "{{ default_domain }}"
```
---

## primary_user
Roles: common, dev

Primary user on the server, typically the one used to administer the system.

Example:
```
primary_user: linda
```

Default:
```
primary_user: admin
```
---

## rejected_addresses
Roles: mail

A dictionary of email addresses to be rejected with error codes and messages. Emails sent to these addresses will cause a bounce back with the error code and message shown.

Example:
```
rejected_addresses:
  - email: no-reply@example.local
    code: '550'
    msg: "No replies, it's in the address..."
```

Default:
```
rejected_addresses: {}
```
---

## rescue_port
Roles: nginx

Backup port to use for nginx if port 80 is already in use.

Example:
```
rescue_port: 8088
```

Default:
```
rescue_port: 8080
```
---

## reset_data
Roles: ldap

When enabled, LDAP data will be provisioned during the play if the LDAP server can't be reached. This value should only be enabled during provisioning to avoid potential data loss.

Example:
```
reset_data: true
```

Default:
```
reset_data: false
```
---

## roundcube_db_name
Roles: roundcube

Name of the roundcube postgresql database.

Example:
```
roundcube_db_name: mail
```

Default:
```
roundcube_db_name: roundcube
```
---

## roundcube_db_password
Roles: roundcube

The roundcube postgresql database password. 

Example:
```
roundcube_db_password : '$ecretPassw0rd.'
```

Default:
```
#roundcube_db_password : ''
```
---

## roundcube_db_username
Roles: roundcube

The roundcube postgresql database username. 

Example:
```
roundcube_db_username: mail
```

Default:
```
roundcube_db_username: roundcube
```

## roundcube_des_key
Roles: roundcube

The DES key used in the roundcube configuration. The playbook will automatically set a random value if left unset.

Example:
```
roundcube_des_key: '34TEPkqOfLnx5vad'
```

Default:
```
roundcube_des_key: ''
```
---

## roundcube_download_url
Roles: roundcube

Download URL for the version of roundcube you wish to use. See https://roundcube.net/download/.

Example:
```
roundcube_download_url: https://github.com/roundcube/roundcubemail/releases/download/1.5.2/roundcubemail-1.5.2-complete.tar.gz
```

Default:
```
roundcube_download_url: 'https://github.com/roundcube/roundcubemail/releases/download/{{ roundcube_version }}/roundcubemail-{{ roundcube_version }}-complete.tar.gz'
```
---

## roundcube_extra_hostnames
Roles: roundcube

Any additional hostnames you wish to use for roundcube.

Example:
```
roundcube_extra_hostnames: 
  - webmail.example.local
  - roundcube.example.local
  - webmail.example2.local
```

Default:
```
roundcube_extra_hostnames: []
```
---

## roundcube_hostname
Roles: roundcube

The primary hostname used for accessing roundcube.

Example:
```
roundcube_hostname: "webmail.example.local"
```

Default:
```
roundcube_hostname: "webmail.{{ default_domain }}"
```
---

## roundcube_ipv6
Roles: roundcube

IPv6 address used for roundcube. Use "false" to disable.

Example:
```
roundcube_ipv6: "2001:db8:1234::6"
```

Default:
```
roundcube_ipv6: "{{ ipv6_address | default(false) }}"
```
---

## roundcube_title
Roles: roundcube

The title for the roundcube website.

Example:
```
roundcube_title: "Roundcube Webmail"
```

Default:
```
roundcube_title: "{{ mail_server.split('.')[1] | capitalize }} Webmail"
```
---

## roundcube_version
Roles: roundcube

Roundcube version to use. Variable is used to check current version and download set version using the default roundcube_download_url. 

Example:
```
roundcube_version: 1.6.0
```

Default:
```
roundcube_version: 1.5.2
```
---

## rspamd_add_header
Roles: mail

Emails with a spam score higher than this will have header information added.

Example:
```
rspamd_add_header: 0
```

Default:
```
rspamd_add_header: 5
```
---

## rspamd_controller_password
Roles: mail

Password used to access the rspamd web dashboard.

Example:
```
rspamd_controller_password: '$ecretPassw0rd.'
```

Default:
```
#rspamd_controller_password: ''
```
---

## rspamd_greylist
Roles: mail

Emails with a spam score higher than this will be greylisted on the server.

Example:
```
rspamd_greylist: 2
```

Default:
```
rspamd_greylist: 4
```
---

## rspamd_hostname
Roles: mail

The hostname for the rspamd web dashboard.

Example:
```
rspamd_hostname: "rspamd.example.local"

```
Default:
```
rspamd_hostname: "rspamd.{{ primary_mail_domain }}"
```
---

## rspamd_ipv6
Roles: mail

IPv6 address for the rspamd web dashboard. 

Example:
```
rspamd_ipv6: 2001:db8:1234::4
```

Default:
```
rspamd_ipv6: "{{ ipv6_address | default(false) }}"
```

## rspamd_list_dbs
Roles: mail

A list of rspamd multimap files to backup/restore.

Example:
```
rspamd_list_dbs:
  - email_deny.inc
  - domain_deny.inc
  - domain_allow.inc
```

Default:
```
rspamd_list_dbs: [email_denylist.inc, domain_denylist.inc, regex_denylist.inc,
                  domain_allowlist.inc, email_allowlist.inc]
```
---

## rspamd_reject
Roles: mail

Emails with a spam score higher than this will be rejected from the server.

Example:
```
rspamd_reject: 10
```

Default:
```
rspamd_reject: 15
```
---

## rspamd_rewrite_subject
Roles: mail

Emails with a spam score higher than this will have their subject rewritten to start with "[SPAM]".

Example:
```
rspamd_rewrite_subject: 4
```

Default:
```
rspamd_rewrite_subject: 8
```
---

## samba_allow_list
Roles: common

A list of IPs/Subnets that can access the smb server.

Eample:
```
samba_allow_list:
  - 192.168.2.30
  - 192.168.2.31
  - 2001:db8:123:123::/64
```

Default:
```
samba_allow_list: []
```
---

## samba_cert_name
Roles: samba

The certbot certificate name used for samba.

Example:
```
samba_cert_name: example.local
```

Default:
```
samba_cert_name: '{{ samba_domain }}'
```
---

## samba_domain
Roles: samba

Domain used for the Samba stand-alone server.

Example:
```
samba_domain: example.local
```

Default:
```
samba_domain: '{{ default_domain }}'
```
---

## samba_extra_domains
Roles: samba

Any additional domains to include with the Samba certbot certificate.

Example:
```
samba_extra_domains:
  - example2.local
```

Default:
```
samba_extra_domains: []
```

## samba_hostname
Roles: samba

The primary hostname used for the stand-alone samba server.

Example:
```
samba_hostname: 'samba.example.local'
```

Default:
```
samba_hostname: 'samba.{{ default_domain }}'
```
---

## samba_ipv6
Roles: common

Opens SMB ports for IPv6 firewall when enabled.

Example:
```
samba_ipv6: true
```

Default:
```
samba_ipv6: false
```
---

## samba_shares
Roles: samba

A dictionary containing the shares to set up under the samba server.

Example:
```
samba_shares:
  downloads: 
    description: Downloads
    path: /home/admin/Downloads
    guest: yes
    force_user: admin
    directory_mask: '2770'
  private:
    description: Personal
    guest: no
    path: /home/admin/secrets
    writeable: 'no'
```

Default:
```
samba_shares: {}
```
---

## samba_users
Roles:

A dictionary containing the samba users and their passwords. 

Example:
```
samba_users:
  admin:
    password: "{{ users.admin.password }}"
  guest:
    password: "guest"
  media:
    password: "{{ smb_password }}"
```

Default:
```
samba_users: {}
```
---

## sieve_port:
Roles: common, mail, roundcube

Port used for connecting to ManageSieve on the mail servers.

Example: 
```
sieve_port: 4190
```

Default:
```
sieve_port: 4190
```
---

## site_css
Roles: site_placeholder

The css filename to use for the site_placeholder website.

Example:
```
site_css: dark.css
```

Default:
```
site_css: default.css
```
---

## site_directory
Roles: site_placeholder

The root folder to hold the site_placeholder website. 

Example:
```
site_directory: /var/www/example.local
```

Default:
```
site_directory: /var/www/construction
```
---

## site_domain
Roles: site_placeholder

The domain/hostname of the site_placeholder website.

Example:
```
site_domain: "example.local"
```

Default:
```
site_domain: "{{ default_domain }}"
```
---

## site_extra_domains
Roles: site_placeholder

Any additional domains/hostnames of the site_placeholder website.

Example:
```
site_extra_domains:
  - www.example.local
```

Default:
```
site_extra_domains: []
```
---

## site_footer
Roles: site_placeholder

Footer message for the site_placeholder website. Useful for including image attribution.

Example:
```
site_footer: '<a href="https://www.flaticon.com/free-icons/quality-control" title="quality control icons">Quality control icons created by Freepik - Flaticon</a>'
```

Default:
```
site_footer: false
```
---

## site_icon
Roles: site_placeholder

The favicon filename for the site_placeholder website.

Example
```
site_icon: favicon.ico
```

Default:
```
site_icon: favicon.png
```
---

## site_img
Roles: site_placeholder

The logo image for the site_placeholder website.

Example:
```
site_img: logo.jpg
```

Default:
```
site_img: logo.png
```
---

## site_img_position
Roles: site_placeholder

The position of the logo image for the site_placeholder website. It can either be 'above' or 'below' the site_msg.

Example:
```
site_img_position: above
```

Default:
```
site_img_position: below
```
---

## site_ip_favicon
Roles: site_ip

The filename for the favicon used for the site_ip website.

Example:
```
site_ip_favicon: favicon.ico
```

Default:
```
site_ip_favicon: favicon.svg
```
---

## site_ip_hostname
Roles: site_ip

The main hostname of the site_ip website, which provides both IPv4 and IPv6 addresses if available.

Example:
```
site_ip_hostname: 'ip.example.local'
```

Default
```
site_ip_hostname: 'ip.{{ default_domain }}'
```
---

## site_ip_ipv6
Roles: site_ip

The IPv6 address used for the site_ip website.

Example:
```
site_ip_ipv6: 2001:db8:1234::1122
```

Default:
```
site_ip_ipv6: '{{ ipv6_address | default(false) }}'
```
---

## site_ip_key
Roles: site_ip

A random key generated for flask used by the site_ip website. It will be set during the play if unset.

Example:
```
site_ip_key: 'wQ65qsAc48aHFGxgt2zoIkuz'
```

Default:
```
site_ip_key: ''
```
---

## site_ip_root
Roles: site_ip

Root directory containing the site_ip website.

Example:
```
site_ip_root: /var/www/ip.example.local
```

Default:
```
site_ip_root: /var/www/site_ip
```
---

## site_ip_theme
Roles: site_ip

The theme/style used for the site_ip website. To create a new theme, clone the default folder under the site_ip role, make the desired changes, then set the variable name to the folder name.

Example:
```
site_ip_theme: dark
```

Default:
```
site_ip_theme: default
```
---

## site_ip_title
Roles: site_ip

Set the title of the site_ip website.

Example:
```
site_ip_title: "Example: What's my IP?"
```

Default:
```
site_ip_title: "What's my IP?"
```
---

## site_ip_v4_hostname
Roles: site_ip

The hostname used for the ipv4 lookup for the site_ip website.

Example:
```
site_ip_v4_hostname: 'ipv4.example.local'
```

Default:
```
site_ip_v4_hostname: 'ipv4.{{ default_domain }}'
```
---

## site_ip_v6_hostname
Roles: site_ip

The hostname used for the ipv6 lookup for the site_ip website.

Example:
```
site_ip_v6_hostname: 'ipv6.example.local'
```

Default:
```
site_ip_v6_hostname: 'ipv6.{{ default_domain }}'
```
---

## site_licenses
Roles: site_placeholder

A list of files in the files/licenses folder to upload with the site_placeholder site. Useful for including licenses for purchased images.

Example:
```
site_licenses:
  - image_license-11111111.pdf
  - favicon_license-11111111.pdf
```

Default:
```
site_licenses: []
```
---

## site_msg
Roles: site_placeholder

The message to display on the site_placeholder website.

Example:
```
site_msg: "Try again later!"
```

Default:
```
site_msg: "This page is currently under construction."
```
---

## site_title
Roles: site_placeholder

The title of the site_placeholder website.

Example:
```
site_title: '{{ inventory_hostname }}'
```

Default:
```
site_title: "Under Construction"
```
---

## smb_password
Roles: emby_server, kodi

The password used for accessing the smb_shares. 

Example:
```
smb_password: media
```

Default:
```
smb_password: ''
```
---

## smb_shares
Roles: emby_server, kodi

A dictionary containing the hostname/IP and share names for our media SMB folders.

Example:
```
smb_shares:
  '192.168.0.15':
    - music
  'nas.example.local':
    - tv 
    - movies
    - downloads
```

Default:
```
smb_shares: {}
```
---

## smb_user
Roles: emby_server, kodi

The username used for accessing the smb_shares.

Example:
```
smb_user: media
```

Default:
```
smb_user: ''
```
---

## smb_workgroup
Roles: kodi

The workgroup name for the SMB shares. 

Example:
```
smb_workgroup: OFFICE
```

Default:
```
smb_workgroup: WORKGROUP
```
---

## smtp_notice_email: 'notice@{{ default_domain }}'
Roles: sendmail

Email address/username used for notification email authentication.

Example:
```
smtp_notice_email: "notice@example.local"
```

Default:
```
smtp_notice_email: 'notice@{{ default_domain }}'
```
---

## smtp_notice_password
Roles: sendmail

Password used for notification email authentication.

Example:
```
smtp_notice_password: '$ecretPassw0rd.'
```

Default:
```
#smtp_notice_password: ''
```
---

## spammed_accounts
Roles: mail

A list of local email accounts that have been discarded because they only receive spam (honey trap). Emails sent to these addresses will be used to train rspamd then discarded.

Example:
```
spammed_accounts:
  - honeypot@example.local
  - info@example.local
  - facebook@example.local
```

Defauult:
```
spammed_accounts: []
```
---

## spf_default_txt
Roles: dns

The default SPF text record used when a DNS zone doesn't have one explicitly defined. See https://www.zytrax.com/books/dns/ch9/spf.html.

Example:
```
spf_default_txt: 'v=spf1 mx ~all'
```

Default:
```
spf_default_txt: 'v=spf1 a mx -all'
```
---

## sshd_keytype
Roles: common

SSH key algorithm to use when working with SSH keys.

Example: 
```
sshd_keytype: rsa
```

Default:
```
sshd_keytype: ed25519
```
---

## sshd_public_port
Roles: common

Allows you to set a non-standard port for SSHD in addition to the locked down regular port. 0 is disabled.

Example: 
```
sshd_public_port: 8022
```

Default:
```
sshd_public_port: 0
```
---

## sshd_service_name
Roles: common

Allows you to set the service name for SSHD as Raspbian is different than Debian.

Example:
```
sshd_service_name: ssh
```

Default:
```
sshd_service_name: sshd
```
---

## sshd_strict_ipv6
Roles: common

When true, SSHD will be set to only listen on the primary IPv6 IP (ipv6_addresss). When false, SSHD will listen on all IPv6 IPs on the host.

Example: 
```
sshd_strict_ipv6: false
```

Default:
```
sshd_strict_ipv6: true
```
---

## sudo_nopasswd
Roles: common

A list of users who can use sudo without a password.

Example:
```
sudo_nopasswd:  
  - admin
```

Default:
```
sudo_nopasswd: []
```
---

## sudo_users
Roles: common

A list of users to give sudo access.

Example:
```
sudo_users:  
  - admin  
  - ansible  
  - linda  
```

Default:
```
sudo_users:  
  - '{{ primary_user }}'  
  - '{{ ansible_ssh_user }}'  
```
---

## timezone
Roles: common

Timezone for the system. See https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for options.

Example:
```
timezone: America/New_York
```

Default:
```
timezone: America/Toronto
```
---

## tld_spam_score
Roles: mail

Allows you to increase the spam score for specific TLDs.

Example:
```
tld_spam_score:
  cam: 5.0
  xxx: 8.0
  info: 3.0
  us: 2.0
```

Default:
```
tld_spam_score: {'cam': 4.0, 'us': 1.0, 'club': 4.0}
```
---

## transmission_allow_list
Roles: common, transmission

A list of trusted IPs/subnets (IPv4 & IPv6) which will be allowed to access the transmission web dashboard.

Example: 
```
transmission_allow_list:
  - 2001:db8:f2c:1234::/56
  - 192.168.1.0/24
  - 10.0.100.5
```

Default:
```
transmission_allow_list: []
```
---

## transmission_alt_day
Roles: transmission

The days to enable the alternate speed. See https://github.com/transmission/transmission/blob/main/docs/Editing-Configuration-Files.md#scheduling for details.

Example:
```
transmission_alt_day: 62
```

Default:
```
transmission_alt_day: 127
```
---

## transmission_alt_download
Roles: transmission

The alternate download speed (kB/s), allowing the torrents to run faster when the connection won't be in use.

Example:
```
transmission_alt_download: 2500
```

Default:
```
transmission_alt_download: 200000
```
---

## transmission_alt_end
Roles: transmission

The end time for the alternate speeds. See https://github.com/transmission/transmission/blob/main/docs/Editing-Configuration-Files.md#scheduling for details.

Example:
```
transmission_alt_end: 1020
```

Default:
```
transmission_alt_end: 480
```
---

## transmission_alt_start
Roles: transmission

The start time for the alternate speeds. See https://github.com/transmission/transmission/blob/main/docs/Editing-Configuration-Files.md#scheduling for details.

Example:
```
transmission_alt_start: 540
```

Default:
```
transmission_alt_start: 120
```
---

## transmission_alt_upload
Roles: transmission

The alternate upload speed (kB/s), allowing the torrents to run faster when the connection won't be in use.

Example:
```
transmission_alt_upload: 750
```

Default:
```
transmission_alt_upload: 10000
```
---

## transmission_cert_name
Roles: transmission

The certbot certificate name for the transmission web dashboard/interface.

Example:
```
transmission_cert_name: example.local
```

Default:
```
transmission_cert_name: '{{ transmission_hostnames | first }}'
```
---

## transmission_download_dir
Roles: transmission

The directory that transmission will save downloads to automatically.

Example:
```
transmission_download_dir: /mnt/downloads
```

Default:
```
transmission_download_dir: /usr/downloads
```
---

## transmission_high_port
Roles: common, transmission

The high end of the randomize ports for transmission.

Example:
```
transmission_high_port: 70000
```

Default:
```
transmission_high_port: 65535
```

## transmission_hostnames
Roles: transmission

Hostnames used for accessing the transmission web dashboard/interface.

Example:
```
transmission_hostnames:
  - 'torrents.example.local'
  - 'transmission.example.local'
```

Default:
```
transmission_hostnames:
  - 'torrents.{{ default_domain }}'
```
---

## tansmission_https
Roles: transmission

Whether to enable https access to the transmission dashboard website.

Example:
```
transmission_https: false
```

Default:
```
transmission_https: true
```
---

## transmission_https_only
Roles: common, transmission

When enabled, the transmission dashboard is only available over HTTPS.

Example:
```
transmission_https_only: true
```

Default:
```
transmission_https_only: false
```
---

## transmission_incomplete_dir
Roles: transmission

The directory transmission will store the download in until it finishes.

Example:
```
transmission_incomplete_dir: /tmp
```

Default:
```
transmission_incomplete_dir: '{{ transmission_download_dir }}/.incomplete'
```
---

## transmission_low_port
Roles: common, transmission

The low end of the randomize ports for transmission.

Example:
```
transmission_low_port: 60000
```

Default:
```
transmission_high_port: 49152
```
---


## transmission_max_download
Roles: transmission

The max download speed (kB/s) for transmission.

Example:
```
transmission_max_download: 1250
```

Default:
```
transmission_max_download: 10000
```
---

## transmission_max_upload
Roles: transmission

The max upload speed (kB/s) for transmission.

Example:
```
transmission_max_upload: 375
```

Default:
```
transmission_max_upload: 5000
```
---

## transmission_mounts
Roles: transmission

A dictionary of SMB mounts to add to the host. Can be used to store the transmission downloads. The username and password for the mounts are set with the **smb_user** and **smb_password** variables.  

Example:
```
transmission_mounts:
  nas.example.local:
    - downloads
```

Default:
```
transmission_mounts: []
```
---

## transmission_queue_size
Roles: transmission

Maximum number of active torrents in transmission.

Example:
```
transmission_queue_size: 4
```

Default:
```
transmission_queue_size: 8
```
---

## transmission_strict_hostnames
Roles: transmission

When true, you can only access transmission by the hostnames defined in transmission_hostnames.

Example:
```
transmission_strict_hostnames: true
```

Default:
```
transmission_strict_hostnames: false
```
---

## transmission_torrent_dir
Roles: transmission

The directory transmission should periodically check for torrent files.

Example:
```
transmission_torrent_dir: /usr/downloads/.torrents
```

Default:
```
transmission_torrent_dir: '{{ transmission_download_dir }}'
```
---

## transmission_vboxguest
Roles: transmission

When true, the transmission role will ensure the vboxguest role is run so that the VM can access the host's drives.

Example:
```
transmission_vboxguest: true
```

Default:
```
transmission_vboxguest: false
```
---

## transmission_vpn
Roles: transmission

When true, an always on Nord VPN connection is enabled on the transmission host. The username and password for Nord are set with the **nordvpn_user** and **nordvpn_password** variables. Use the **nordvpn_country** variable to set the country endpoint for the Nord VPN, default is Canada.

Example:
```
transmission_vpn: true
```

Default:
```
transmission_vpn: false
```
---

## trusted_hosts
Roles: common, mail

A list of trusted IPs/subnets (IPv4 & IPv6) which will get added to several service allow lists, including SSHD.

Example: 
```
trusted_hosts:
  - 2001:db8:f2c:1234::/56
  - 192.168.1.0/24
  - 10.0.100.5
```

Default:
```
trusted_hosts: []
```
---

## users
Roles: common

A dictionary containing basic user information to add to all host. This variable should be in an ansible-vault file. 

Example:
```
users:
  admin
    password: "SecretPassword"
  ansible:
    password: "Unique_{{ inventory_hostname_short[:2] }}_Password"
```

Defaut:
```
users: []
```
---

## vbox_version
Roles: virtualbox

Version of VirtualBox to install.

Example:
```
vbox_version: 6.1
```

Default:
```
vbox_version: 7.0
```
---

## vboxsf_user
Roles: vboxguest

The user given access to virtualbox shared media folders by adding them to the vboxfs group.

Example:
```
vboxsf_user: 'admin'
```

Default:
```
vboxsf_user: '{{ primary_user }}'
```
---

## vm_list
Roles: virtualbox

A list of virtualbox VMs to start automatically upon boot for vm_user.

Example:
```
vm_list:
  - seedbox.example.local
  - apps.example.local
```

Default:
```
vm_list: []
```

## vm_user
Roles: virtualbox

The user that runs the virtualbox machines defined in vm_list. 

Example:
```
vm_user: admin
```

Default:
```
vm_user: '{{ primary_user }}'
```

## website_ipv6
Roles: common

A list of IPv6 addresses used for serving websites. This list is used to allow the traffic through the firewall. 

Example: 
```
website_ipv6:
  - 2001:db8:c2ee::a1
  - 2001:db8:c2ee::a2
  - 2001:db8:c2ee::a3
  - 2001:db8:c2ee::a3
```

Default:
```
website_ipv6: []
```
---

## wg_clients
Roles: wireguard

A dictionary of clients including their public key, IPV4 and optionally IPv6 addresses.

Example:
```
wg_clients:
  Android:
    public_key: BxCxRGb5amcBslKZDmcjZBFGjpQOc3nUrXkH3M5xjiQ=
    ipv4: 10.10.10.2
    ipv6: 2001:db8:1:2::2/128
  Work_Laptop:
    public_key: RvCxRGb5amcBslKzDmcjZeFGjpQOc3nUrXkH3K2xqip=
    ipv4: 10.10.10.3
    ipv6: 2001:db8:1:2::3/128
```

Default:
```
wg_clients: []
```
---

## wg_ipv4_subnet
Roles: common, wireguard

IPv4 subnet used by WireGuard.

Example:
```
wg_ipv4_subnet: 192.168.10.1/24
```

Default:
```
wg_subnet: 10.0.10.1/24
```
---

## wg_ipv6_subnet
Roles: common, wireguard

IPv4 subnet used by WireGuard. Set to false to disable.

Example:
```
wg_ipv6_subnet: 2001:db8:1:2::1/64
```

Default:
```
wg_ipv6_subnet: fc10:1:2::1/64
```
---

## wg_nat
Roles: common, wiregaurd

Enables NAT for IPv6 on the WireGuard server. Useful when the server only has a single IPv6 address.

Example:
```
wg_nat: true
```

Default:
```
wg_nat: false
```
---

## wg_port
Roles: common, wireguard

Set the port used for WireGuard.

Example:
```
wg_port: 51194
```

Default:
```
wg_port: 51820
```
---

## wg_psk
Roles: wireguard

Generates a pre shared key and configures WireGuard to use it. Key is added to host's host_vars file.

Example:
```
wg_psk: true
```

Default:
```
wg_psk: false
```
---

## wg_sysctrl
Roles: wireguard

A list of sysctl values to enable on the WireGuard server.

Example:
```
wg_sysctl:
  - net.ipv4.ip_forward
```

Default:
```
wg_sysctl:
  - net.ipv4.ip_forward
  - net.ipv6.conf.all.forwarding
  - net.ipv6.conf.default.forwarding
  - 'net.ipv6.conf.{{ default_if | default(ansible_facts.default_ipv4.alias) }}.proxy_ndp'
```
---

## wiki_cert_name
Roles: wiki

The name used for the wiki certbot certificate.

Example:
```
wiki_cert_name: example.local
```

Default:
```
wiki_cert_name: '{{ default_domain }}'
```
---

## wiki_hostnames
Roles: wiki

A list of hostnames that can be used to access the wiki/Raneto instance.

Example:
```
wiki_hostnames: 
  - wiki.example.local
  - docs.example.local
```

Default:
```
wiki_hostnames: 
  - 'wiki.{{ default_domain }}'
```
---

## wiki_ipv6:
Roles: wiki

IPv6 address used for the wiki/Raneto site. Use "false" to disabled IPv6.

Example:
```
wiki_ipv6: 2001:db8:1234::18

```

Default:
```
wiki_ipv6: False
```
---

## wiki_support_email
Roles: wiki

Email address used for the "Get in touch" footer on the wiki pages.

Example:
```
wiki_support_email: wiki_help@example.local
```

Default:
```
wiki_support_email: `wiki@{{ default_domain }}'
```
---

## wiki_title:
Roles: wiki

The title used for the wiki/Raneto site.

Example:
```
wiki_title: Example Wiki
```

Default:
```
wiki_title: Example Docs
```
---
