# benchmarks.py

LINUX_BENCHMARKS = [
        # Kernel module checks
    {
        "id": "1.1.1.1",
        "level": "1",
        "type": "kernel_module_disabled",
        "module": "cramfs",
        "description": "Ensure cramfs kernel module is not available"
    },
    {
        "id": "1.1.2.1",
        "level": "1",
        "type": "file_exists",
        "path": "/etc/passwd",
        "description": "Ensure /etc/passwd exists"
    },
    {
        "id": "1.1.1.2",
        "level": "1",
        "type": "kernel_module_disabled",
        "module": "freevxfs",
        "description": "Ensure freevxfs kernel module is not available (Automated)"
    },
    {
        "id": "1.1.1.3",
        "level": "1",
        "type": "kernel_module_disabled",
        "module": "hfs",
        "description": "Ensure hfs kernel module is not available (Automated)"
    },
    {
        "id": "1.1.1.4",
        "level": "1",
        "type": "kernel_module_disabled",
        "module": "hfsplus",
        "description": "Ensure hfsplus kernel module is not available (Automated)"
    },
    {
        "id": "1.1.1.5",
        "level": "1",
        "type": "kernel_module_disabled",
        "module": "jffs2",
        "description": "Ensure jffs2 kernel module is not available (Automated)"
    },
    {
        "id": "1.1.1.10",
        "level": "1",
        "type": "manual",
        "description": "Ensure unused filesystems kernel modules are not available (Manual)"
    },
     # Partition checks
    {
        "id": "1.1.2.1.1",
        "level": "1",
        "type": "partition_mounted",
        "partition": "/tmp",
        "description": "Ensure /tmp is a separate partition (Automated)"
    },
    {
        "id": "1.1.2.1.2",
        "level": "1",
        "type": "partition_option",
        "partition": "/tmp",
        "option": "nodev",
        "description": "Ensure nodev option set on /tmp partition (Automated)"
    },
    {
        "id": "1.1.2.1.3",
        "level": "1",
        "type": "partition_option",
        "partition": "/tmp",
        "option": "nosuid",
        "description": "Ensure nosuid option set on /tmp partition (Automated)"
    },
    {
        "id": "1.1.2.1.4",
        "level": "1",
        "type": "partition_option",
        "partition": "/tmp",
        "option": "noexec",
        "description": "Ensure noexec option set on /tmp partition (Automated)"
    },
    {
        "id": "1.1.2.2.1",
        "level": "1",
        "type": "partition_mounted",
        "partition": "/dev/shm",
        "description": "Ensure /dev/shm is a separate partition (Automated)"
    },
    {
        "id": "1.1.2.2.2",
        "level": "1",
        "type": "partition_option",
        "partition": "/dev/shm",
        "option": "nodev",
        "description": "Ensure nodev option set on /dev/shm partition (Automated)"
    },
    {
        "id": "1.1.2.2.3",
        "level": "1",
        "type": "partition_option",
        "partition": "/dev/shm",
        "option": "nosuid",
        "description": "Ensure nosuid option set on /dev/shm partition (Automated)"
    },
    {
        "id": "1.1.2.2.4",
        "level": "1",
        "type": "partition_option",
        "partition": "/dev/shm",
        "option": "noexec",
        "description": "Ensure noexec option set on /dev/shm partition (Automated)"
    },
    # /dev/shm partition checks
    {
        "id": "1.1.2.2.1",
        "level": "1",
        "type": "partition_mounted",
        "partition": "/dev/shm",
        "description": "Ensure /dev/shm is a separate partition (Automated)"
    },
    {
        "id": "1.1.2.2.2",
        "level": "1",
        "type": "partition_option",
        "partition": "/dev/shm",
        "option": "nodev",
        "description": "Ensure nodev option set on /dev/shm partition (Automated)"
    },
    {
        "id": "1.1.2.2.3",
        "level": "1",
        "type": "partition_option",
        "partition": "/dev/shm",
        "option": "nosuid",
        "description": "Ensure nosuid option set on /dev/shm partition (Automated)"
    },
    {
        "id": "1.1.2.2.4",
        "level": "1",
        "type": "partition_option",
        "partition": "/dev/shm",
        "option": "noexec",
        "description": "Ensure noexec option set on /dev/shm partition (Automated)"
    },

    # /home partition checks
    {
        "id": "1.1.2.3.2",
        "level": "1",
        "type": "partition_option",
        "partition": "/home",
        "option": "nodev",
        "description": "Ensure nodev option set on /home partition (Automated)"
    },
    {
        "id": "1.1.2.3.3",
        "level": "1",
        "type": "partition_option",
        "partition": "/home",
        "option": "nosuid",
        "description": "Ensure nosuid option set on /home partition (Automated)"
    },

    # /var partition checks
    {
        "id": "1.1.2.4.2",
        "level": "1",
        "type": "partition_option",
        "partition": "/var",
        "option": "nodev",
        "description": "Ensure nodev option set on /var partition (Automated)"
    },
    {
        "id": "1.1.2.4.3",
        "level": "1",
        "type": "partition_option",
        "partition": "/var",
        "option": "nosuid",
        "description": "Ensure nosuid option set on /var partition (Automated)"
    },

    # /var/tmp partition checks
    {
        "id": "1.1.2.5.2",
        "level": "1",
        "type": "partition_option",
        "partition": "/var/tmp",
        "option": "nodev",
        "description": "Ensure nodev option set on /var/tmp partition (Automated)"
    },
    {
        "id": "1.1.2.5.3",
        "level": "1",
        "type": "partition_option",
        "partition": "/var/tmp",
        "option": "nosuid",
        "description": "Ensure nosuid option set on /var/tmp partition (Automated)"
    },
    {
        "id": "1.1.2.5.4",
        "level": "1",
        "type": "partition_option",
        "partition": "/var/tmp",
        "option": "noexec",
        "description": "Ensure noexec option set on /var/tmp partition (Automated)"
    },

    # /var/log partition checks
    {
        "id": "1.1.2.6.2",
        "level": "1",
        "type": "partition_option",
        "partition": "/var/log",
        "option": "nodev",
        "description": "Ensure nodev option set on /var/log partition (Automated)"
    },
    {
        "id": "1.1.2.6.3",
        "level": "1",
        "type": "partition_option",
        "partition": "/var/log",
        "option": "nosuid",
        "description": "Ensure nosuid option set on /var/log partition (Automated)"
    },
    {
        "id": "1.1.2.6.4",
        "level": "1",
        "type": "partition_option",
        "partition": "/var/log",
        "option": "noexec",
        "description": "Ensure noexec option set on /var/log partition (Automated)"
    },
    #-----------
     {
        "id": "1.1.2.7.2",
        "level": "1",
        "type": "partition_option",
        "partition": "/var/log/audit",
        "option": "nodev",
        "description": "Ensure nodev option set on /var/log/audit partition (Automated)"
    },
    {
        "id": "1.1.2.7.3",
        "level": "1",
        "type": "partition_option",
        "partition": "/var/log/audit",
        "option": "nosuid",
        "description": "Ensure nosuid option set on /var/log/audit partition (Automated)"
    },
    {
        "id": "1.1.2.7.4",
        "level": "1",
        "type": "partition_option",
        "partition": "/var/log/audit",
        "option": "noexec",
        "description": "Ensure noexec option set on /var/log/audit partition (Automated)"
    },
    {
        "id": "1.3.1.1",
        "level": "1",
        "type": "check_package_installed",
        "package": "apparmor",
        "description": "Ensure AppArmor is installed (Automated)"
    },
    {
        "id": "1.3.1.2",
        "level": "1",
        "type": "apparmor_status",
        "status": "enabled",
        "description": "Ensure AppArmor is enabled in the bootloader configuration (Automated)"
    },
    {
        "id": "1.3.1.3",
        "level": "1",
        "type": "apparmor_status",
        "status": "enforce",
        "description": "Ensure all AppArmor Profiles are in enforce or complain mode (Automated)"
    },
    {
        "id": "1.3.1.4",
        "level": "1",
        "type": "apparmor_status",
        "status": "enforce",
        "description": "Ensure all AppArmor Profiles are enforcing (Automated)"
    },
    {
        "id": "1.4.1",
        "level": 1,
        "type": "bootloader_password",
        "description": "Ensure bootloader password is set (Automated)"
    },
    {
    "id": "1.4.2",
    "level": 1,
    "type": "bootloader_permissions",
    "description": "Ensure permissions on bootloader config are configured",
    },
    {
        "id": "1.5.1",
        "description": "Ensure address space layout randomization is enabled",
        "type": "aslr_enabled",
        "level": 1
    },
    {
        "id": "1.5.2",
        "description": "Ensure ptrace_scope is restricted",
        "type": "ptrace_scope",
        "level": 1
    },
    {
        "id": "1.5.3",
        "description": "Ensure core dumps are restricted",
        "type": "coredumps_restricted",
        "level": 1
    },
    {
        "id": "1.5.4",
        "level": "1",
        "type": "check_package_absent",
        "package": "prelink",
        "description": "Ensure prelink is not installed (Automated)"
    },
    {
        "id": "1.5.5",
        "level": "1",
        "type": "check_service_disabled",
        "service": "apport",
        "description": "Ensure Automatic Error Reporting is not enabled (Automated)"
    },
     {
        "id": "1.6.1",
        "description": "Ensure message of the day is configured properly",
        "type": "motd_configured",
        "level": "1"
    },
    {
        "id": "1.6.2",
        "description": "Ensure local login warning banner is configured properly",
        "type": "issue_configured",
        "level": "1"
    },
    {
        "id": "1.6.3",
        "description": "Ensure remote login warning banner is configured properly",
        "type": "issue_net_configured",
        "level": "1"
    },
    {
        "id": "1.6.4",
        "description": "Ensure access to /etc/motd is configured",
        "type": "motd_access",
        "level": "1"
    },
    {
        "id": "1.6.5",
        "description": "Ensure access to /etc/issue is configured",
        "type": "issue_access",
        "level": "1"
    },
    {
        "id": "1.6.6",
        "description": "Ensure access to /etc/issue.net is configured",
        "type": "issue_net_access",
        "level": "1"
    },
    {
        "id": "1.7.2",
        "description": "Ensure GDM login banner is configured",
        "type": "gdm_banner_configured",
        "level": "1"
    },
    {
        "id": "1.7.3",
        "description": "Ensure GDM disable-user-list option is enabled",
        "type": "gdm_disable_user_list",
        "level": "1"
    },
    {
        "id": "1.7.4",
        "description": "Ensure GDM screen locks when the user is idle",
        "type": "gdm_idle_lock_enabled",
        "level": "1"
    },
    {
        "id": "1.7.5",
        "description": "Ensure GDM screen locks cannot be overridden",
        "type": "gdm_lock_override",
        "level": "1"
    },
    {
        "id": "1.7.8",
        "description": "Ensure GDM autorun-never is enabled",
        "type": "gdm_autorun_never_enabled",
        "level": "1"
    },
    {
        "id": "1.7.9",
        "description": "Ensure GDM autorun-never is not overridden",
        "type": "gdm_autorun_never_locked",
        "level": "1"
    },
    {
        "id": "1.7.10",
        "description": "Ensure XDMCP is not enabled",
        "type": "xdmcp_disabled",
        "level": "1"
    },
    {
        "id": "2.1.3",
        "description": "Ensure DHCP server services are not in use",
        "type": "services_not_in_use",
        "services": ["isc-dhcp-server", "dhcpd"],
        "level": "1"
    },
    {
        "id": "2.1.4",
        "description": "Ensure DNS server services are not in use",
        "type": "services_not_in_use",
        "services": ["bind9", "named"],
        "level": "1"
    },
    {
        "id": "2.1.5",
        "description": "Ensure dnsmasq services are not in use",
        "type": "services_not_in_use",
        "services": ["dnsmasq"],
        "level": "1"
    },
    {
        "id": "2.1.6",
        "description": "Ensure FTP server services are not in use",
        "type": "services_not_in_use",
        "services": ["vsftpd", "proftpd", "pure-ftpd"],
        "level": "1"
    },
    {
        "id": "2.1.7",
        "description": "Ensure LDAP server services are not in use",
        "type": "services_not_in_use",
        "services": ["slapd"],
        "level": "1"
    },
    {
        "id": "2.1.8",
        "description": "Ensure message access server services are not in use",
        "type": "services_not_in_use",
        "services": ["dovecot", "cyrus-imapd"],
        "level": "1"
    },
    {
        "id": "2.1.9",
        "description": "Ensure network file system services are not in use",
        "type": "services_not_in_use",
        "services": ["nfs-server", "rpcbind", "nfs-common"],
        "level": "1"
    },
    {
        "id": "2.1.10",
        "description": "Ensure NIS server services are not in use",
        "type": "services_not_in_use",
        "services": ["ypserv"],
        "level": "1"
    },
    {
        "id": "2.1.11",
        "description": "Ensure print server services are not in use",
        "type": "services_not_in_use",
        "services": ["cups"],
        "level": "1"
    },
    {
        "id": "2.1.12",
        "description": "Ensure rpcbind services are not in use",
        "type": "services_not_in_use",
        "services": ["rpcbind"],
        "level": "1"
    },
    {
        "id": "2.1.13",
        "description": "Ensure rsync services are not in use",
        "type": "services_not_in_use",
        "services": ["rsync"],
        "level": "1"
    },
    {
        "id": "2.1.14",
        "description": "Ensure Samba file server services are not in use",
        "type": "services_not_in_use",
        "services": ["smbd", "nmbd"],
        "level": "1"
    },
    {
        "id": "2.1.15",
        "description": "Ensure SNMP services are not in use",
        "type": "services_not_in_use",
        "services": ["snmpd"],
        "level": "1"
    },
    {
        "id": "2.1.16",
        "description": "Ensure TFTP server services are not in use",
        "type": "services_not_in_use",
        "services": ["tftpd", "tftpd-hpa"],
        "level": "1"
    },
    {
        "id": "2.1.17",
        "description": "Ensure web proxy server services are not in use",
        "type": "services_not_in_use",
        "services": ["squid"],
        "level": "1"
    },
    {
        "id": "2.1.18",
        "description": "Ensure web server services are not in use",
        "type": "services_not_in_use",
        "services": ["apache2", "httpd", "nginx"],
        "level": "1"
    },
    {
        "id": "2.1.19",
        "description": "Ensure xinetd services are not in use",
        "type": "services_not_in_use",
        "services": ["xinetd"],
        "level": "1"
    },
    {
        "id": "2.1.21",
        "description": "Ensure mail transfer agent is configured for local-only mode",
        "type": "manual",  # Or implement a custom check if needed
        "level": "1"
    },
    {
        "id": "2.1.22",
        "description": "Ensure only approved services are listening on a network interface",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "2.2.1",
        "description": "Ensure NIS Client is not installed",
        "type": "package_not_installed",
        "package": "nis",
        "level": "1"
    },
    {
        "id": "2.2.2",
        "description": "Ensure rsh client is not installed",
        "type": "package_not_installed",
        "package": "rsh-client",
        "level": "1"
    },
    {
        "id": "2.2.3",
        "description": "Ensure talk client is not installed",
        "type": "package_not_installed",
        "package": "talk",
        "level": "1"
    },
    {
        "id": "2.2.4",
        "description": "Ensure telnet client is not installed",
        "type": "package_not_installed",
        "package": "telnet",
        "level": "1"
    },
    {
        "id": "2.2.5",
        "description": "Ensure ldap client is not installed",
        "type": "package_not_installed",
        "package": "ldap-utils",
        "level": "1"
    },
    {
        "id": "2.2.6",
        "description": "Ensure ftp client is not installed",
        "type": "package_not_installed",
        "package": "ftp",
        "level": "1"
    },
    {
    "id": "2.3.1.1",
    "description": "Ensure a single time synchronization daemon is in use",
    "type": "single_time_sync_daemon",
    "level": "1"
    },
    {
        "id": "2.3.2.1",
        "description": "Ensure systemd-timesyncd configured with authorized timeserver",
        "type": "timesyncd_configured",
        "level": "1"
    },
    {
        "id": "2.3.2.2",
        "description": "Ensure systemd-timesyncd is enabled and running",
        "type": "timesyncd_enabled_running",
        "level": "1"
    },
    {
        "id": "2.3.3.1",
        "description": "Ensure chrony is configured with authorized timeserver",
        "type": "chrony_configured",
        "level": "1"
    },
    {
        "id": "2.3.3.2",
        "description": "Ensure chrony is running as user _chrony",
        "type": "chrony_user",
        "level": "1"
    },
    {
        "id": "2.3.3.3",
        "description": "Ensure chrony is enabled and running",
        "type": "chrony_enabled_running",
        "level": "1"
    },
    {
        "id": "2.4.1.1",
        "description": "Ensure cron daemon is enabled and active",
        "type": "cron_enabled_running",
        "level": "1"
    },
    {
        "id": "2.4.1.2",
        "description": "Ensure permissions on /etc/crontab are configured",
        "type": "file_permissions",
        "path": "/etc/crontab",
        "mode": "600",
        "level": "1"
    },
    {
        "id": "2.4.1.3",
        "description": "Ensure permissions on /etc/cron.hourly are configured",
        "type": "file_permissions",
        "path": "/etc/cron.hourly",
        "mode": "700",
        "level": "1"
    },
    {
        "id": "2.4.1.4",
        "description": "Ensure permissions on /etc/cron.daily are configured",
        "type": "file_permissions",
        "path": "/etc/cron.daily",
        "mode": "700",
        "level": "1"
    },
    {
        "id": "2.4.1.5",
        "description": "Ensure permissions on /etc/cron.weekly are configured",
        "type": "file_permissions",
        "path": "/etc/cron.weekly",
        "mode": "700",
        "level": "1"
    },
    {
        "id": "2.4.1.6",
        "description": "Ensure permissions on /etc/cron.monthly are configured",
        "type": "file_permissions",
        "path": "/etc/cron.monthly",
        "mode": "700",
        "level": "1"
    },
    {
        "id": "2.4.1.7",
        "description": "Ensure permissions on /etc/cron.d are configured",
        "type": "file_permissions",
        "path": "/etc/cron.d",
        "mode": "700",
        "level": "1"
    },
    {
        "id": "2.4.1.8",
        "description": "Ensure crontab is restricted to authorized users",
        "type": "crontab_restricted",
        "level": "1"
    },
    {
        "id": "2.4.2.1",
        "description": "Ensure at is restricted to authorized users",
        "type": "restricted_at_users",
        "level": "1"
    },
    #new from here(AI help)
    {
        "id": "2.4.2.1",
        "description": "Ensure at is restricted to authorized users",
        "type": "restricted_at_users",
        "level": "1"
    },
    {
        "id": "3.1.1",
        "description": "Ensure IPv6 status is identified",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "3.3.1",
        "description": "Ensure ip forwarding is disabled",
        "type": "sysctl_setting",
        "parameter": "net.ipv4.ip_forward",
        "expected_value": "0",
        "level": "1"
    },
    {
        "id": "3.3.2",
        "description": "Ensure packet redirect sending is disabled",
        "type": "sysctl_setting",
        "parameter": "net.ipv4.conf.all.send_redirects",
        "expected_value": "0",
        "level": "1"
    },
    {
        "id": "3.3.3",
        "description": "Ensure bogus icmp responses are ignored",
        "type": "sysctl_setting",
        "parameter": "net.ipv4.icmp_ignore_bogus_error_responses",
        "expected_value": "1",
        "level": "1"
    },
    {
        "id": "3.3.4",
        "description": "Ensure broadcast icmp requests are ignored",
        "type": "sysctl_setting",
        "parameter": "net.ipv4.icmp_echo_ignore_broadcasts",
        "expected_value": "1",
        "level": "1"
    },
    {
        "id": "3.3.5",
        "description": "Ensure icmp redirects are not accepted",
        "type": "sysctl_setting",
        "parameter": "net.ipv4.conf.all.accept_redirects",
        "expected_value": "0",
        "level": "1"
    },
    {
        "id": "3.3.6",
        "description": "Ensure secure icmp redirects are not accepted",
        "type": "sysctl_setting",
        "parameter": "net.ipv4.conf.all.secure_redirects",
        "expected_value": "0",
        "level": "1"
    },
    {
        "id": "3.3.7",
        "description": "Ensure reverse path filtering is enabled",
        "type": "sysctl_setting",
        "parameter": "net.ipv4.conf.all.rp_filter",
        "expected_value": "1",
        "level": "1"
    },
    {
        "id": "3.3.8",
        "description": "Ensure source routed packets are not accepted",
        "type": "sysctl_setting",
        "parameter": "net.ipv4.conf.all.accept_source_route",
        "expected_value": "0",
        "level": "1"
    },
    {
        "id": "3.3.9",
        "description": "Ensure suspicious packets are logged",
        "type": "sysctl_setting",
        "parameter": "net.ipv4.conf.all.log_martians",
        "expected_value": "1",
        "level": "1"
    },
    {
        "id": "3.3.10",
        "description": "Ensure TCP SYN Cookies is enabled",
        "type": "sysctl_setting",
        "parameter": "net.ipv4.tcp_syncookies",
        "expected_value": "1",
        "level": "1"
    },
    {
        "id": "3.3.11",
        "description": "Ensure IPv6 router advertisements are not accepted",
        "type": "sysctl_setting",
        "parameter": "net.ipv6.conf.all.accept_ra",
        "expected_value": "0",
        "level": "1"
    },

    # Section 4 - Firewall Configuration
    {
        "id": "4.1.1",
        "description": "Ensure a single firewall configuration utility is in use",
        "type": "automated",
        "level": "1"
    },
    
    # 4.2 Configure UFW
    {
        "id": "4.2.1",
        "description": "Ensure ufw is installed",
        "type": "package_check",
        "package": "ufw",
        "level": "1"
    },
    {
        "id": "4.2.2",
        "description": "Ensure iptables-persistent is not installed with ufw",
        "type": "package_absence_check",
        "package": "iptables-persistent",
        "level": "1"
    },
    {
        "id": "4.2.3",
        "description": "Ensure ufw service is enabled",
        "type": "service_enabled_check",
        "service": "ufw",
        "level": "1"
    },
    {
        "id": "4.2.4",
        "description": "Ensure ufw loopback traffic is configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.2.5",
        "description": "Ensure ufw outbound connections are configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.2.6",
        "description": "Ensure ufw firewall rules exist for all open ports",
        "type": "automated",
        "level": "1"
    },
    {
        "id": "4.2.7",
        "description": "Ensure ufw default deny firewall policy",
        "type": "automated",
        "level": "1"
    },

    # 4.3 Configure nftables
    {
        "id": "4.3.1",
        "description": "Ensure nftables is installed",
        "type": "package_check",
        "package": "nftables",
        "level": "1"
    },
    {
        "id": "4.3.2",
        "description": "Ensure ufw is uninstalled or disabled with nftables",
        "type": "package_absence_check",
        "package": "ufw",
        "level": "1"
    },
    {
        "id": "4.3.3",
        "description": "Ensure iptables are flushed with nftables",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.3.4",
        "description": "Ensure a nftables table exists",
        "type": "automated",
        "level": "1"
    },
    {
        "id": "4.3.5",
        "description": "Ensure nftables base chains exist",
        "type": "automated",
        "level": "1"
    },
    {
        "id": "4.3.6",
        "description": "Ensure nftables loopback traffic is configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.3.7",
        "description": "Ensure nftables outbound and established connections are configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.3.8",
        "description": "Ensure nftables default deny firewall policy",
        "type": "automated",
        "level": "1"
    },
    {
        "id": "4.3.9",
        "description": "Ensure nftables service is enabled",
        "type": "service_enabled_check",
        "service": "nftables",
        "level": "1"
    },
    {
        "id": "4.3.10",
        "description": "Ensure nftables rules are permanent",
        "type": "automated",
        "level": "1"
    },

    # 4.4 Configure iptables
    {
        "id": "4.4.1.1",
        "description": "Ensure iptables packages are installed",
        "type": "package_check",
        "package": "iptables",
        "level": "1"
    },
    {
        "id": "4.4.1.2",
        "description": "Ensure nftables is not in use with iptables",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.4.1.3",
        "description": "Ensure ufw is not in use with iptables",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.4.2.1",
        "description": "Ensure iptables default deny firewall policy",
        "type": "automated",
        "level": "1"
    },
    {
        "id": "4.4.2.2",
        "description": "Ensure iptables loopback traffic is configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.4.2.3",
        "description": "Ensure iptables outbound and established connections are configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.4.2.4",
        "description": "Ensure iptables firewall rules exist for all open ports",
        "type": "automated",
        "level": "1"
    },

    # 4.4.3 Configure IPv6 ip6tables
    {
        "id": "4.4.3.1",
        "description": "Ensure ip6tables default deny firewall policy",
        "type": "automated",
        "level": "1"
    },
    {
        "id": "4.4.3.2",
        "description": "Ensure ip6tables loopback traffic is configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.4.3.3",
        "description": "Ensure ip6tables outbound and established connections are configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "4.4.3.4",
        "description": "Ensure ip6tables firewall rules exist for all open ports",
        "type": "automated",
        "level": "1"
    },
    # Section 5 - Access, Authentication, Authorization

    # 5.2 Secure SSH Server Configuration
    {
        "id": "5.2.1",
        "description": "Ensure permissions on /etc/ssh/sshd_config are configured",
        "type": "file_permission_check",
        "file": "/etc/ssh/sshd_config",
        "expected_permission": "600",
        "level": "1"
    },
    {
        "id": "5.2.2",
        "description": "Ensure SSH Protocol is set to 2",
        "type": "sshd_config_check",
        "parameter": "Protocol",
        "expected_value": "2",
        "level": "1"
    },
    {
        "id": "5.2.3",
        "description": "Ensure SSH LogLevel is appropriate",
        "type": "sshd_config_check",
        "parameter": "LogLevel",
        "expected_value": "VERBOSE",
        "level": "1"
    },
    {
        "id": "5.2.4",
        "description": "Ensure SSH X11 forwarding is disabled",
        "type": "sshd_config_check",
        "parameter": "X11Forwarding",
        "expected_value": "no",
        "level": "1"
    },
    {
        "id": "5.2.5",
        "description": "Ensure SSH MaxAuthTries is set to 4 or less",
        "type": "sshd_config_check_max",
        "parameter": "MaxAuthTries",
        "expected_max_value": 4,
        "level": "1"
    },
    {
        "id": "5.2.6",
        "description": "Ensure SSH IgnoreRhosts is enabled",
        "type": "sshd_config_check",
        "parameter": "IgnoreRhosts",
        "expected_value": "yes",
        "level": "1"
    },
    {
        "id": "5.2.7",
        "description": "Ensure SSH HostbasedAuthentication is disabled",
        "type": "sshd_config_check",
        "parameter": "HostbasedAuthentication",
        "expected_value": "no",
        "level": "1"
    },
    # check this benchmarks ...this is not in CIS Ubuntu 20.04
    {
        "id": "5.2.8",
        "description": "Ensure SSH root login is disabled",
        "type": "sshd_config_check",
        "parameter": "PermitRootLogin",
        "expected_value": "no",
        "level": "1"
    },
    #
    {
        "id": "5.1.1",
        "description": "Ensure permissions on /etc/ssh/sshd_config are configured",
        "type": "ssh_file_permissions",
        "path": "/etc/ssh/sshd_config",
        "mode": "600",
        "level": "1"
    },
    {
        "id": "5.1.2",
        "description": "Ensure permissions on SSH private host key files are configured",
        "type": "ssh_file_permissions",
        "path": "/etc/ssh/*_key",
        "mode": "600",
        "level": "1"
    },
    {
        "id": "5.1.3",
        "description": "Ensure permissions on SSH public host key files are configured",
        "type": "ssh_file_permissions",
        "path": "/etc/ssh/*_key.pub",
        "mode": "644",
        "level": "1"
    },
    {
        "id": "5.1.4",
        "description": "Ensure sshd access is configured",
        "type": "sshd_access_configured",
        "level": "1"
    },
    {
        "id": "5.1.5",
        "description": "Ensure sshd Banner is configured",
        "type": "sshd_banner",
        "level": "1"
    },
    {
        "id": "5.1.6",
        "description": "Ensure sshd Ciphers are configured",
        "type": "sshd_ciphers",
        "level": "1"
    },
    {
        "id": "5.1.7",
        "description": "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured",
        "type": "sshd_clientalive",
        "level": "1"
    },
    {
        "id": "5.1.8",
        "description": "Ensure sshd DisableForwarding is enabled",
        "type": "sshd_disable_forwarding",
        "level": "1"
    },
    {
        "id": "5.1.9",
        "description": "Ensure sshd GSSAPIAuthentication is disabled",
        "type": "sshd_gssapiauth_disabled",
        "level": "1"
    },
    {
        "id": "5.1.10",
        "description": "Ensure sshd HostbasedAuthentication is disabled",
        "type": "sshd_hostbasedauth_disabled",
        "level": "1"
    },
    {
        "id": "5.1.11",
        "description": "Ensure sshd IgnoreRhosts is enabled",
        "type": "sshd_ignorerhosts_enabled",
        "level": "1"
    },
    {
        "id": "5.1.12",
        "description": "Ensure sshd KexAlgorithms is configured",
        "type": "sshd_kexalgorithms",
        "level": "1"
    },
    {
        "id": "5.1.13",
        "description": "Ensure sshd LoginGraceTime is configured",
        "type": "sshd_logingracetime",
        "level": "1"
    },
    {
        "id": "5.1.14",
        "description": "Ensure sshd LogLevel is configured",
        "type": "sshd_loglevel",
        "level": "1"
    },
    {
        "id": "5.1.15",
        "description": "Ensure sshd MACs are configured",
        "type": "sshd_macs",
        "level": "1"
    },
    {
        "id": "5.1.16",
        "description": "Ensure sshd MaxAuthTries is configured",
        "type": "sshd_maxauthtries",
        "level": "1"
    },
    {
        "id": "5.1.17",
        "description": "Ensure sshd MaxSessions is configured",
        "type": "sshd_maxsessions",
        "level": "1"
    },
    {
        "id": "5.1.18",
        "description": "Ensure sshd MaxStartups is configured",
        "type": "sshd_maxstartups",
        "level": "1"
    },
    {
        "id": "5.1.19",
        "description": "Ensure sshd PermitEmptyPasswords is disabled",
        "type": "sshd_permitemptypasswords_disabled",
        "level": "1"
    },
    {
        "id": "5.1.20",
        "description": "Ensure sshd PermitRootLogin is disabled",
        "type": "sshd_permitrootlogin_disabled",
        "level": "1"
    },
    {
        "id": "5.1.21",
        "description": "Ensure sshd PermitUserEnvironment is disabled",
        "type": "sshd_permituserenvironment_disabled",
        "level": "1"
    },
    {
        "id": "5.1.22",
        "description": "Ensure sshd UsePAM is enabled",
        "type": "sshd_usepam_enabled",
        "level": "1"
    },

    # these benchmarks are not in CIS Ubuntu 20.04 means these are  not correctly implemented
    {
        "id": "5.2.9",
        "description": "Ensure SSH PermitEmptyPasswords is disabled",
        "type": "sshd_config_check",
        "parameter": "PermitEmptyPasswords",
        "expected_value": "no",
        "level": "1"
    },
    {
        "id": "5.2.10",
        "description": "Ensure SSH PermitUserEnvironment is disabled",
        "type": "sshd_config_check",
        "parameter": "PermitUserEnvironment",
        "expected_value": "no",
        "level": "1"
    },
    {
        "id": "5.2.11",
        "description": "Ensure SSH Idle Timeout Interval is configured",
        "type": "sshd_timeout_check",
        "parameters": ["ClientAliveInterval", "ClientAliveCountMax"],
        "expected_values": {"ClientAliveInterval": 300, "ClientAliveCountMax": 0},
        "level": "1"
    },
    {
        "id": "5.2.12",
        "description": "Ensure SSH LoginGraceTime is set to one minute or less",
        "type": "sshd_config_check_max",
        "parameter": "LoginGraceTime",
        "expected_max_seconds": 60,
        "level": "1"
    },
    {
        "id": "5.2.13",
        "description": "Ensure SSH access is limited",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "5.2.14",
        "description": "Ensure SSH warning banner is configured",
        "type": "sshd_config_check",
        "parameter": "Banner",
        "expected_value": "/etc/issue.net",
        "level": "1"
    },

    # 5.3 Configure PAM
    {
        "id": "5.3.1",
        "description": "Ensure password creation requirements are configured",
        "type": "pam_pwquality_check",
        "level": "1"
    },
    {
        "id": "5.3.2",
        "description": "Ensure lockout for failed password attempts is configured",
        "type": "pam_tally_check",
        "level": "1"
    },
    {
        "id": "5.3.3",
        "description": "Ensure password reuse is limited",
        "type": "pam_pwhistory_check",
        "level": "1"
    },
    {
        "id": "5.3.4",
        "description": "Ensure password hashing algorithm is SHA-512",
        "type": "pam_password_hash_check",
        "expected_value": "sha512",
        "level": "1"
    },

    # Section 6 - System Maintenance

    # 6.1 System File Permissions
    {
        "id": "6.1.1",
        "description": "Audit system file permissions",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "6.1.2",
        "description": "Ensure permissions on /etc/passwd are configured",
        "type": "file_permission_check",
        "file": "/etc/passwd",
        "expected_permission": "644",
        "level": "1"
    },
    {
        "id": "6.1.3",
        "description": "Ensure permissions on /etc/shadow are configured",
        "type": "file_permission_check",
        "file": "/etc/shadow",
        "expected_permission": "000",
        "level": "1"
    },
    {
        "id": "6.1.4",
        "description": "Ensure permissions on /etc/group are configured",
        "type": "file_permission_check",
        "file": "/etc/group",
        "expected_permission": "644",
        "level": "1"
    },
    {
        "id": "6.1.5",
        "description": "Ensure permissions on /etc/gshadow are configured",
        "type": "file_permission_check",
        "file": "/etc/gshadow",
        "expected_permission": "000",
        "level": "1"
    },

    # Section 7 - Application Security

    # 7.1 Time Synchronization
    {
        "id": "7.1.1",
        "description": "Ensure time synchronization is in use",
        "type": "service_check",
        "services": ["chronyd", "ntpd", "systemd-timesyncd"],
        "level": "1"
    },
    {
        "id": "7.1.2",
        "description": "Ensure systemd-timesyncd is configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "7.1.3",
        "description": "Ensure chrony is configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "7.1.4",
        "description": "Ensure ntp is configured",
        "type": "manual",
        "level": "1"
    },
    
    # Section 7.2 - Mail Transfer Agent
    {
        "id": "7.2.1",
        "description": "Ensure mail transfer agent is configured for local-only mode",
        "type": "manual",
        "level": "1"
    },

    # Section 7.3 - Automatic Updates
    {
        "id": "7.3.1",
        "description": "Ensure package manager repositories are configured",
        "type": "manual",
        "level": "1"
    },
    {
        "id": "7.3.2",
        "description": "Ensure system is up-to-date",
        "type": "manual",
        "level": "1"
    }

]

