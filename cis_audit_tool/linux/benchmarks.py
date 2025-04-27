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
        "id": "2.1.3",
        "level": "1",
        "type": "check_service_disabled",
        "service": "isc-dhcp-server",
        "description": "Ensure DHCP server services are not in use (Automated)"
    },
    {
        "id": "2.1.4",
        "level": "1",
        "type": "check_service_disabled",
        "service": "bind9",
        "description": "Ensure DNS server services are not in use (Automated)"
    },
    {
        "id": "2.2.1",
        "level": "1",
        "type": "check_package_absent",
        "package": "nis",
        "description": "Ensure NIS Client is not installed (Automated)"
    },
    {
        "id": "2.2.2",
        "level": "1",
        "type": "check_package_absent",
        "package": "rsh-client",
        "description": "Ensure rsh client is not installed (Automated)"
    },
    {
        "id": "2.2.3",
        "level": "1",
        "type": "check_package_absent",
        "package": "talk",
        "description": "Ensure talk client is not installed (Automated)"
    },
    {
        "id": "2.2.4",
        "level": "1",
        "type": "check_package_absent",
        "package": "telnet",
        "description": "Ensure telnet client is not installed (Automated)"
    },
    {
        "id": "2.3.2.2",
        "level": "1",
        "type": "check_service_enabled",
        "service": "systemd-timesyncd",
        "description": "Ensure systemd-timesyncd is enabled and running (Automated)"
    },
    {
        "id": "2.4.1.1",
        "level": "1",
        "type": "check_service_enabled",
        "service": "cron",
        "description": "Ensure cron daemon is enabled and active (Automated)"
    },
    {
        "id": "2.4.1.2",
        "level": "1",
        "type": "check_file_permissions",
        "file": "/etc/crontab",
        "permissions": "600",
        "description": "Ensure permissions on /etc/crontab are configured (Automated)"
    },
    {
        "id": "2.4.1.8",
        "level": "1",
        "type": "check_file_ownership",
        "file": "/etc/cron.allow",
        "owner": "root",
        "description": "Ensure crontab is restricted to authorized users (Automated)"
    }

]

