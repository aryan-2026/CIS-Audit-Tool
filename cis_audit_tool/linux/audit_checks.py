import subprocess
import os
import shlex
import logging
from .benchmarks import LINUX_BENCHMARKS

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

### Helper function to run shell commands
def run_command(cmd):
    """Runs a shell command and returns True if successful, False otherwise."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0 or not result.stdout.strip():
            logging.debug(f"Command failed: {cmd}\nOutput: {result.stdout}\nError: {result.stderr}")
            return False
        return True
    except Exception as e:
        logging.error(f"Error executing command: {cmd}\n{e}")
        return False

### Secure shell quoting
def quote(val):
    return shlex.quote(val)

### Checks
def check_kernel_module_disabled(module):
    return not run_command(f"lsmod | grep -w {quote(module)}")

def check_partition_mounted(partition):
    return run_command(f"mount | grep -w {quote(partition)}")

def check_partition_option(partition, option):
    return run_command(f"mount | grep -w {quote(partition)} | grep -w {quote(option)}")

def check_apparmor_installed():
    return run_command("dpkg-query -W apparmor")

def check_apparmor_enabled():
    return run_command("apparmor_status | grep 'enabled'")

def check_apparmor_enforce():
    return run_command("apparmor_status | grep 'enforce'")

def check_bootloader_password():
    return run_command("grep 'password' /boot/grub/grub.cfg")

def check_bootloader_permissions():
    return run_command("stat -c %a /boot/grub/grub.cfg | grep -w '600'")

def check_aslr_enabled():
    return run_command("sysctl kernel.randomize_va_space | grep -w '2'")

def check_ptrace_scope():
    return run_command("sysctl kernel.yama.ptrace_scope | grep -w '1'")

def check_coredumps_restricted():
    return run_command("sysctl fs.suid_dumpable | grep -w '0'")

def check_prelink_not_installed():
    return not run_command("dpkg-query -W prelink")

def check_auto_error_reporting_disabled():
    return run_command("systemctl is-enabled apport | grep -w 'disabled'")

def check_file_permissions(path, mode):
    return run_command(f"stat -c %a {quote(path)} | grep -w {quote(mode)}")

# motd starts here
def check_motd_access():
    return check_file_permissions("/etc/motd", "644")
def check_motd_configured():
    try:
        with open("/etc/motd", "r") as f:
            content = f.read()
            # Simple check: ensure it contains a warning
            return "unauthorized" in content.lower() or "warning" in content.lower()
    except Exception as e:
        logging.error(f"Error reading /etc/motd: {e}")
        return False

def check_issue_configured():
    try:
        with open("/etc/issue", "r") as f:
            content = f.read()
            # Look for warning content
            return "unauthorized" in content.lower() or "warning" in content.lower()
    except Exception as e:
        logging.error(f"Error reading /etc/issue: {e}")
        return False
def check_issue_access():
    return check_file_permissions("/etc/issue", "644")

def check_issue_net_access():
    return check_file_permissions("/etc/issue.net", "644")
# motd ends here
#Configure GNOME Display Manager
def check_gsettings_value(schema, key, expected_value):
    try:
        result = subprocess.run(
            ["gsettings", "get", schema, key],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            logging.error(f"GSettings query failed: {schema} {key}")
            return False
        return expected_value.lower() in result.stdout.strip().lower()
    except Exception as e:
        logging.error(f"GSettings check error: {schema} {key} - {e}")
        return False
def check_gdm_lock_cannot_be_overridden():
    return check_gsettings_value("org.gnome.desktop.screensaver", "user-switch-enabled", "false")
def check_gdm_autorun_never_enabled():
    return check_gsettings_value("org.gnome.desktop.media-handling", "autorun-never", "true")
def check_gdm_autorun_never_not_overridden():
    return run_command("grep -r 'org/gnome/desktop/media-handling/autorun-never' /etc/dconf/db/local.d/locks")
def check_xdmcp_disabled():
    try:
        with open("/etc/gdm/custom.conf", "r") as f:
            lines = f.readlines()
            in_xdmcp = False
            for line in lines:
                line = line.strip()
                if line.lower() == "[xdmcp]":
                    in_xdmcp = True
                elif line.startswith("[") and in_xdmcp:
                    in_xdmcp = False
                elif in_xdmcp and "enable" in line.lower():
                    return "false" in line.lower()
        return True  # If Enable= not found, assume disabled
    except Exception as e:
        logging.error(f"Error checking XDMCP: {e}")
        return False

# config of GNOME Display Manager ends here
def check_services_not_in_use(services):
    for service in services:
        # Check if installed
        if run_command(f"dpkg-query -W {quote(service)}"):
            # Check if enabled
            if run_command(f"systemctl is-enabled {quote(service)} | grep -v 'disabled'"):
                return False
            # Check if active
            if run_command(f"systemctl is-active {quote(service)} | grep -v 'inactive'"):
                return False
    return True

def check_single_time_sync_daemon():
    daemons = [
        {"name": "systemd-timesyncd", "cmd": "systemctl is-enabled systemd-timesyncd"},
        {"name": "chrony", "cmd": "systemctl is-enabled chronyd"},
        {"name": "ntpd", "cmd": "systemctl is-enabled ntpd"},
    ]
    enabled = 0
    for daemon in daemons:
        if run_command(f"{daemon['cmd']} | grep -w 'enabled'"):
            enabled += 1
    return enabled == 1
def check_timesyncd_configured():
    return run_command("grep -E '^(NTP|FallbackNTP)=' /etc/systemd/timesyncd.conf")
def check_timesyncd_enabled_running():
    return (run_command("systemctl is-enabled systemd-timesyncd | grep -w 'enabled'") and
            run_command("systemctl is-active systemd-timesyncd | grep -w 'active'"))
def check_chrony_configured():
    return run_command("grep -E '^server ' /etc/chrony/chrony.conf")
def check_chrony_user():
    return run_command("ps -eo user,comm | grep chronyd | grep -w '_chrony'")
def check_chrony_enabled_running():
    return (run_command("systemctl is-enabled chronyd | grep -w 'enabled'") and
            run_command("systemctl is-active chronyd | grep -w 'active'"))

def check_cron_enabled_running():
    return (run_command("systemctl is-enabled cron | grep -w 'enabled'") and
            run_command("systemctl is-active cron | grep -w 'active'"))
def check_crontab_restricted():
    return (not os.path.exists("/etc/cron.deny") and
            os.path.exists("/etc/cron.allow") and
            check_file_permissions("/etc/cron.allow", "600"))
def check_restricted_at_users():
    return (not os.path.exists("/etc/at.deny") and 
            os.path.exists("/etc/at.allow") and
            check_file_permissions("/etc/at.allow", "600"))

def check_sshd_access_configured():
    return run_command(
        "grep -Ei '^(AllowUsers|DenyUsers|AllowGroups|DenyGroups)' /etc/ssh/sshd_config"
    )
def check_sshd_banner():
    return run_command("grep -E '^[^#]*Banner' /etc/ssh/sshd_config")
def check_sshd_ciphers():
    return run_command("grep -E '^[^#]*Ciphers' /etc/ssh/sshd_config")
def check_sshd_clientalive():
    interval_ok = run_command("grep -E '^[^#]*ClientAliveInterval' /etc/ssh/sshd_config")
    countmax_ok = run_command("grep -E '^[^#]*ClientAliveCountMax' /etc/ssh/sshd_config")
    return interval_ok and countmax_ok
def check_sshd_disable_forwarding():
    return run_command("grep -E '^[^#]*AllowTcpForwarding\\s+no' /etc/ssh/sshd_config")
def check_sshd_gssapiauth_disabled():
    return run_command("grep -E '^[^#]*GSSAPIAuthentication\\s+no' /etc/ssh/sshd_config")
def check_sshd_hostbasedauth_disabled():
    return run_command("grep -E '^[^#]*HostbasedAuthentication\\s+no' /etc/ssh/sshd_config")
def check_sshd_ignorerhosts_enabled():
    return run_command("grep -E '^[^#]*IgnoreRhosts\\s+yes' /etc/ssh/sshd_config")
def check_sshd_kexalgorithms():
    return run_command("grep -E '^[^#]*KexAlgorithms' /etc/ssh/sshd_config")
def check_sshd_logingracetime():
    return run_command("grep -E '^[^#]*LoginGraceTime' /etc/ssh/sshd_config")
def check_sshd_loglevel():
    return run_command("grep -E '^[^#]*LogLevel' /etc/ssh/sshd_config")
def check_sshd_macs():
    return run_command("grep -E '^[^#]*MACs' /etc/ssh/sshd_config")
def check_sshd_maxauthtries():
    return run_command("grep -E '^[^#]*MaxAuthTries' /etc/ssh/sshd_config")
def check_sshd_maxsessions():
    return run_command("grep -E '^[^#]*MaxSessions' /etc/ssh/sshd_config")
def check_sshd_maxstartups():
    return run_command("grep -E '^[^#]*MaxStartups' /etc/ssh/sshd_config")
def check_sshd_permitemptypasswords_disabled():
    return run_command("grep -E '^[^#]*PermitEmptyPasswords\\s+no' /etc/ssh/sshd_config")
def check_sshd_permitrootlogin_disabled():
    return run_command("grep -E '^[^#]*PermitRootLogin\\s+no' /etc/ssh/sshd_config")
def check_sshd_permituserenvironment_disabled():
    return run_command("grep -E '^[^#]*PermitUserEnvironment\\s+no' /etc/ssh/sshd_config")
def check_sshd_usepam_enabled():
    return run_command("grep -E '^[^#]*UsePAM\\s+yes' /etc/ssh/sshd_config")


def check_sysctl_setting(param, expected):
    return run_command(f"sysctl {quote(param)} | grep -w {quote(expected)}")

def check_multiple_sysctl(params):
    return all(check_sysctl_setting(p, v) for p, v in params.items())

def check_package_installed(package):
    return run_command(f"dpkg-query -W {quote(package)}")

def check_package_not_installed(package):
    return not check_package_installed(package)

def check_sshd_config_setting(directive, value):
    return run_command(f"grep -E '^\\s*{quote(directive)}\\s+{quote(value)}\\s*$' /etc/ssh/sshd_config | grep -v '^\\s*#'")

def check_ufw_enabled():
    return run_command("systemctl is-enabled ufw | grep -w 'enabled'")

def check_ufw_loopback():
    return (run_command("ufw status | grep 'Anywhere on lo'") and
            run_command("ufw status | grep 'Anywhere DENY'"))

def check_ufw_default_deny():
    return (run_command("ufw status verbose | grep 'deny (incoming)'") and
            run_command("ufw status verbose | grep 'deny (outgoing)'") and
            run_command("ufw status verbose | grep 'deny (routed)'"))

def check_nftables_table_exists():
    return run_command("nft list tables")

def check_nftables_service_enabled():
    return run_command("systemctl is-enabled nftables | grep -w 'enabled'")

def check_iptables_default_deny(ipv6=False):
    cmd = "ip6tables" if ipv6 else "iptables"
    return (run_command(f"{cmd} -L INPUT | grep 'DROP'") and
            run_command(f"{cmd} -L FORWARD | grep 'DROP'") and
            run_command(f"{cmd} -L OUTPUT | grep 'DROP'"))

def check_ssh_file_permissions(path, mode):
    return check_file_permissions(path, mode)

def check_sudo_installed():
    return check_package_installed("sudo")

def check_sudo_pty():
    return run_command("grep -Ei '^\\s*Defaults\\s+use_pty' /etc/sudoers")

def check_pam_module_enabled(module, file, control):
    return run_command(f"grep -E '^\\s*{quote(control)}\\s+{quote(module)}' {quote(file)}")

def check_aide_installed():
    return check_package_installed("aide")

def check_aide_cron():
    return run_command("crontab -u root -l | grep aide")

def check_file_integrity():
    return os.path.exists("/var/lib/aide/aide.db")

### Dispatcher Function
def check_dispatcher(benchmark):
    check_functions = {
        "kernel_module_disabled": lambda b: check_kernel_module_disabled(b["module"]),
        "partition_mounted": lambda b: check_partition_mounted(b["partition"]),
        "partition_option": lambda b: check_partition_option(b["partition"], b["option"]),
        "apparmor_installed": lambda _: check_apparmor_installed(),
        "apparmor_enabled": lambda _: check_apparmor_enabled(),
        "apparmor_enforce": lambda _: check_apparmor_enforce(),
        "bootloader_password": lambda _: check_bootloader_password(),
        "bootloader_permissions": lambda _: check_bootloader_permissions(),
        "aslr_enabled": lambda _: check_aslr_enabled(),
        "ptrace_scope": lambda _: check_ptrace_scope(),
        "coredumps_restricted": lambda _: check_coredumps_restricted(),
        "prelink_not_installed": lambda _: check_prelink_not_installed(),
        "auto_error_reporting_disabled": lambda _: check_auto_error_reporting_disabled(),
        "motd_access": lambda _: check_motd_access(),
        "motd_configured": lambda _: check_motd_configured(),
        "issue_configured": lambda _: check_issue_configured(),
        "issue_access": lambda _: check_issue_access(),
        "issue_net_access": lambda _: check_issue_net_access(),
        "gdm_banner_configured": lambda _: check_gsettings_value("org.gnome.login-screen", "banner-message-enable", "true"),
        "gdm_disable_user_list": lambda _: check_gsettings_value("org.gnome.login-screen", "disable-user-list", "true"),
        "gdm_idle_lock_enabled": lambda _: check_gsettings_value("org.gnome.desktop.screensaver", "lock-enabled", "true"),
        "gdm_lock_override": lambda _: check_gdm_lock_cannot_be_overridden(),
        "gdm_autorun_never_enabled": lambda _: check_gdm_autorun_never_enabled(),
        "gdm_autorun_never_locked": lambda _: check_gdm_autorun_never_not_overridden(),
        "xdmcp_disabled": lambda _: check_xdmcp_disabled(),
        "services_not_in_use": lambda b: check_services_not_in_use(b["services"]),
        #"service_not_installed": lambda b: check_service_not_installed(b["service"]),
        "single_time_sync_daemon": lambda _: check_single_time_sync_daemon(),
        "timesyncd_configured": lambda _: check_timesyncd_configured(),
        "timesyncd_enabled_running": lambda _: check_timesyncd_enabled_running(),
        "chrony_configured": lambda _: check_chrony_configured(),
        "chrony_user": lambda _: check_chrony_user(),
        "chrony_enabled_running": lambda _: check_chrony_enabled_running(),
        "cron_enabled_running": lambda _: check_cron_enabled_running(),
        "crontab_restricted": lambda _: check_crontab_restricted(),
        "restricted_at_users": lambda _: check_restricted_at_users(),
        "sshd_access_configured": lambda _: check_sshd_access_configured(),
        "sshd_banner": lambda _: check_sshd_banner(),
        "sshd_ciphers": lambda _: check_sshd_ciphers(),
        "sshd_clientalive": lambda _: check_sshd_clientalive(),
        "sshd_disable_forwarding": lambda _: check_sshd_disable_forwarding(),
        "sshd_gssapiauth_disabled": lambda _: check_sshd_gssapiauth_disabled(),
        "sshd_hostbasedauth_disabled": lambda _: check_sshd_hostbasedauth_disabled(),
        "sshd_ignorerhosts_enabled": lambda _: check_sshd_ignorerhosts_enabled(),
        "sshd_kexalgorithms": lambda _: check_sshd_kexalgorithms(),
        "sshd_logingracetime": lambda _: check_sshd_logingracetime(),
        "sshd_loglevel": lambda _: check_sshd_loglevel(),
        "sshd_macs": lambda _: check_sshd_macs(),
        "sshd_maxauthtries": lambda _: check_sshd_maxauthtries(),
        "sshd_maxsessions": lambda _: check_sshd_maxsessions(),
        "sshd_maxstartups": lambda _: check_sshd_maxstartups(),
        "sshd_permitemptypasswords_disabled": lambda _: check_sshd_permitemptypasswords_disabled(),
        "sshd_permitrootlogin_disabled": lambda _: check_sshd_permitrootlogin_disabled(),
        "sshd_permituserenvironment_disabled": lambda _: check_sshd_permituserenvironment_disabled(),
        "sshd_usepam_enabled": lambda _: check_sshd_usepam_enabled(),

        "sysctl_setting": lambda b: check_sysctl_setting(b["parameter"], b["expected_value"]),
        "multiple_sysctl": lambda b: check_multiple_sysctl(b["params"]),
        "package_installed": lambda b: check_package_installed(b["package"]),
        "package_not_installed": lambda b: check_package_not_installed(b["package"]),
        "file_permissions": lambda b: check_file_permissions(b["path"], b["mode"]),
        "sshd_config_setting": lambda b: check_sshd_config_setting(b["directive"], b["value"]),
        "ufw_enabled": lambda _: check_ufw_enabled(),
        "ufw_loopback": lambda _: check_ufw_loopback(),
        "ufw_default_deny": lambda _: check_ufw_default_deny(),
        "nftables_table_exists": lambda _: check_nftables_table_exists(),
        "nftables_service_enabled": lambda _: check_nftables_service_enabled(),
        "iptables_default_deny": lambda b: check_iptables_default_deny(b.get("ipv6", False)),
        "ssh_file_permissions": lambda b: check_ssh_file_permissions(b["path"], b["mode"]),
        "sudo_installed": lambda _: check_sudo_installed(),
        "sudo_pty": lambda _: check_sudo_pty(),
        "pam_module_enabled": lambda b: check_pam_module_enabled(b["module"], b["file"], b["control"]),
        "aide_installed": lambda _: check_aide_installed(),
        "aide_cron": lambda _: check_aide_cron(),
        "file_integrity": lambda _: check_file_integrity(),
        "manual": lambda _: False,
    }

    check_func = check_functions.get(benchmark["type"])
    return check_func(benchmark) if check_func else False

### Run Audit Function
def run_linux_audit(config=None, level=None, includes=None, excludes=None):
    results = []
    for benchmark in LINUX_BENCHMARKS:
        # Apply filters with proper type handling
        if level is not None:
            # Convert both to strings for comparison to handle mixed types
            benchmark_level = str(benchmark.get("level", ""))
            filter_level = str(level)
            if benchmark_level != filter_level:
                continue
            
        if includes and benchmark["id"] not in includes:
            continue
            
        if excludes and benchmark["id"] in excludes:
            continue

        status = check_dispatcher(benchmark)
        status_str = "MANUAL" if benchmark["type"] == "manual" else "PASS" if status else "FAIL"
        
        result_str = f"{benchmark['id']}: {status_str} - {benchmark['description']}"
        logging.info(result_str)

        results.append({
            "id": benchmark["id"],
            "status": status_str,
            "description": benchmark["description"]
        })

    # Summary
    logging.info("\nAudit Summary:")
    passed = sum(r['status'] == 'PASS' for r in results)
    failed = sum(r['status'] == 'FAIL' for r in results)
    manual = sum(r['status'] == 'MANUAL' for r in results)
    logging.info(f"Passed: {passed}")
    logging.info(f"Failed: {failed}")
    logging.info(f"Manual: {manual}")

    return results