# Roles


## backblaze

The backblaze role installs the backblaze b2 script and configures the encrypted backup jobs defined under the backblaze_backups variable.

_Required variables_: **backblaze_backups**, **blackblaze_ssec_keys**, **backblaze_app_id**

## cerbot

The certbot role uses nginx to create Let's Encrypt SSL certificates. Hostname/domain A/AAAA records must be setup and pointing to the server running certbot for the role to work.

_Required variables_: **cert_domain**

## cerbot_dns

The certbot_dns role sets up Let's Encrypt certificates by directly contacting the master authoritative DNS server running Bind9 (dns role) using an RNDC keyfile. Currently, the dns role configuration only supports top level wildcard domains (e.g. *.example.local).

_Required variables_: **cert_name**, **cert_domains**, **cert_dns_server**

## common

The common role is a base role, intended to be run on all hosts to do some basic house keeping including installing core apps, setting up default users, configuring the network/firewall and some basic system settings.

_Required variables_: **users**, **primary_user**

## dashy

The dashy role sets up an instance of [dashy](https://github.com/Lissy93/dashy) created by [Lissy93](https://github.com/Lissy93). The role backs up the configuration whenever it's run which can be cloned/restored on other hosts.

_Required variables_: **dashy_hostnames**

## dev

The dev role performs basic tasks to get it ready as my developer VM. It installs/configures ansible and installs packages useful for running the various roles.

_Required variables_: None

## dns

The DNS role sets up bind9 as an authoritative DNS server. The role supports multiple secondary instances with the primary server being defined by the first item listed in the nameservers variable. DNSSEC can be enabled per domain.

_Required variables_: **ns_domain**, **nameservers**, **mail_domains**, **dns_zones**

## emby

The emby role sets up an emby server instance that use SMB shares to access network media. Server is intended to be accessed over the WAN, using a firewall allow list to only allow specific IPs/Subnets. The role can back up and restore data, but by default assumes there is only one instance of the data per environment.

_Required variables_: **emby_hostnames**, **media_shares**, **media_user**, **media_password**

## files

The files role sets up an instance of [Jirafeau](https://gitlab.com/mojo42/Jirafeau) by [mojo42](https://gitlab.com/mojo42). Custom styles can be created in the files folder by cloning an existing media folder and updating the contents.

_Required variables_: **files_hostnames**, **files_admin_password**

## kodi

The kodi role installs and configures [kodi](https://kodi.tv/) instances, intended to be run off a Raspberry Pi. The role includes SMB mounts for accessing media on network shares. The role is set to automatically backup and restore the Kodi data.

_Required variables_: **media_shares**, **media_user**, **media_password**

## ldap

The ldap role installs openldap/slapd and configures it to be used with the mail role. By default, the role generates certificates through certbot to enable TLS. It's possible to enable data replication between LDAP hosts. The role includes a basic script for creating/resetting accounts. The role can backup and restore the LDAP data.

_Required variables_: **ldap_hostname**, **ldap_rootpw**, **ldap_pw**, **mail_domains**

## mail

The mail role installs postfix, dovecot and rspamd. Dovecot/Postfix use LDAP as the backend for email accounts. The role enables the rspamd web dashboard, but only for IPs in the trusted_hosts variable.

_Required variables_: **primary_mail_domain**, **mail_hostname**, **rspamd_hostname**, **rspamd_controller_password**, **ldap_pw**

## nginx

The nginx role simply installs nginx and ensure the ssl-certs group exists and includes the nginx user. 

_Required variables_: None

## pbx

The PBX role creates and installs a Let's Encrypt certificate for Asterisk/FreePBX and installs the software required for converting audio formats for dealing with sound recordings. The role is set to backup the backup files created through the dashboard Backup & Restore module.

_Required variables_: **pbx_hostnames**

## pihole

The pihole deploys [pihole](https://pi-hole.net/) on a system and configures it with the provided forwarders. Additionally, it will configure the local domains if local_dns_zones is enable. It's possible to enable HTTPS for the pihole dashboard by generating a certifcate with certbot_dns.

_Required variables_: **pihole_hostnames**, **pihole_password**

## roundcube

The roundcube role installs/upgrades and configures the roundcube webmail software. The role will backup and restore the roundcube postgresql data.

_Required variables_: **roundcube_hostname**, **mail_server**, **roundcube_db_password**, **postgresql_root_password**, **ldap_admin**, **ldap_pw**

## samba

The samba role installs Samba as a stand alone file server to be used by samba_users for the shares defined in samba_shares. The role uses certbot_dns to generate the SSL certificate.

_Required variables_: **samba_hostname**, **samba_users**, **samba_shares**

## sendmail

The sendmail role installs and configures sendmail on a host to work with the defined mail server. The primary purpose of this role is to ensure hosts will send out the cron emails.

_Required variables_: **mail_server**, **smtp_notice_email**, **smtp_notice_password**

## site_ip

The site_ip role sets up a basic "What is my IP?" website using flask/javascript. The role requires 3 hostnames to work, the IPv4 hostname, the IPv6 hostname and the landing page hostname.

_Required variables_: **ip_site_hostname**, **ip_site_v4_hostname**, **ip_site_v6_hostname**

## site_placeholder

The site_placeholder role sets up a basic landing page with a logo, favicon and message using nginx. Useful for placeholder/under construction messages.

_Required variables_: **site_domain**

## transmission

The transmission role sets up the transmission bittorrent client/dashboard. It allows you to configure an SMB mount or VirtualBox shared folder as the download directory. You can also enable an always on NordVPN connection. You can enable HTTPS access to the transmission dashboard which uses the certbot_dns and nginx roles to create a reverse proxy.

_Required variables_: **transmission_hostnames**, **transmission_download_dir**

## unifi_network

The unifi_network role sets up an instance of a Ubiquity Unifi Network controller, using certbot_dns to generate a wildcard ssl certificate. This role does not configure or backup/restore the data for Unifi Network.

_Required variables_: **unifi_network_cert_name**, **unifi_network_domains**

## unifi_video

(Depreacated) The unifi_video role sets up an instance of Ubiquity's Unifi Video software which has been discontinued as they attempt to force users to use Unifi Protect which doesn't run on custom hardware. The role uses certbot_dns to generate the SSL certificate. This role does not configure or backup/restore the data for Unifi-Video.

This role cannot be used on the same host as the unifi_network role.

_Required variables_: **unifi_video_cert_name**, **unifi_video_domains**

## vboxguest

The vboxguest role installs the apps required to build the guest additions for VirtualBox, and then builds them by running the script on the included ISO, if inserted. The host will be rebooted after the installation to apply the changes.

_Required variables_: **primary_user**

## virtualbox

The virtualbox role installs Oracle VM VirtualBox and adds cronjob starting VMs listed under the vm_names variable in headless mode.

_Required variables_: None