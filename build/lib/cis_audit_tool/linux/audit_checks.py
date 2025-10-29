import subprocess
import os
import shlex
import time 
import re
import logging
from .benchmarks import LINUX_BENCHMARKS

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

### Helper function to run shell commands
def run_command(cmd):
    """Runs a shell command and returns (success, output)."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout.strip() + ("\n" + result.stderr.strip() if result.stderr.strip() else "")
        # success = True if returncode is 0 AND output is not empty (for checks that expect output)
        # For general commands, success is just returncode == 0
        success = result.returncode == 0
        return success, output
    except Exception as e:
        return False, str(e)

### Secure shell quoting
def quote(val):
    return shlex.quote(val)

# ----------------------------------------------
# --- NEW FUNCTION FOR FILE EXISTENCE CHECK ----
# ----------------------------------------------
def check_file_exists(path):
    """
    Checks if a file or directory exists at the given path.
    This explicitly addresses checks like 'Ensure /etc/passwd exists'.
    """
    return os.path.exists(path)

# ----------------------------------------------------
# --- NEW FUNCTION FOR SUID/SGID LISTING (7.1.13) ----
# ----------------------------------------------------
def check_suid_sgid_file_list():
    """
    Finds all SUID/SGID files for manual review (7.1.13).
    Returns success status and the list of files found.
    """
    # Find files with SUID (-4000) or SGID (-2000) bits set, excluding separate filesystems
    find_cmd = "find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -print"
    # Note: run_command uses returncode 0 for success, which is what we need here,
    # even if the list is long.
    return run_command(find_cmd)

### Checks
def check_kernel_module_disabled(module):
    success, output = run_command(f"lsmod | grep -w {quote(module)}")
    return not success  # True if module is NOT loaded


def check_partition_mounted(partition):
    success, _ = run_command(f"mount | grep -w {quote(partition)}")
    return success


def check_partition_option(partition, option):
    success, _ = run_command(f"mount | grep -w {quote(partition)} | grep -w {quote(option)}")
    return success


def check_apparmor_installed():
    success, _ = run_command("dpkg-query -W apparmor")
    return success

def check_apparmor_enabled():
    success, _ = run_command("apparmor_status | grep 'enabled'")
    return success

def check_apparmor_enforce():
    success, _ = run_command("apparmor_status | grep 'enforce'")
    return success


def check_bootloader_password():
    success, _ = run_command("grep 'password' /boot/grub/grub.cfg")
    return success

def check_bootloader_permissions():
    success, _ = run_command("stat -c %a /boot/grub/grub.cfg | grep -w '600'")
    return success


def check_aslr_enabled():
    success, output = run_command("sysctl kernel.randomize_va_space")
    return output.strip().endswith("2")

def check_ptrace_scope():
    success, output = run_command("sysctl kernel.yama.ptrace_scope")
    return output.strip().endswith("1")

def check_coredumps_restricted():
    success, output = run_command("sysctl fs.suid_dumpable")
    return output.strip().endswith("0")


def check_prelink_not_installed():
    success, _ = run_command("dpkg-query -W prelink")
    return not success  # True if package is not installed


def check_auto_error_reporting_disabled():
    success, _ = run_command("systemctl is-enabled apport | grep -w 'disabled'")
    return success

def check_file_permissions(path, mode):
    success, _ = run_command(f"stat -c %a {quote(path)} | grep -w {quote(mode)}")
    return success


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
        logging.debug(f"Error reading /etc/motd: {e}")
        return False

def check_issue_configured():
    try:
        with open("/etc/issue", "r") as f:
            content = f.read()
            # Look for warning content
            return "unauthorized" in content.lower() or "warning" in content.lower()
    except Exception as e:
        logging.debug(f"Error reading /etc/issue: {e}")
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
            logging.debug(f"GSettings query failed: {schema} {key}")
            return False
        return expected_value.lower() in result.stdout.strip().lower()
    except Exception as e:
        logging.debug(f"GSettings check error: {schema} {key} - {e}")
        return False
def check_gdm_lock_cannot_be_overridden():
    return check_gsettings_value("org.gnome.desktop.screensaver", "user-switch-enabled", "false")
def check_gdm_autorun_never_enabled():
    return check_gsettings_value("org.gnome.desktop.media-handling", "autorun-never", "true")
def check_gdm_autorun_never_not_overridden():
    success, _ = run_command("grep -r 'org/gnome/desktop/media-handling/autorun-never' /etc/dconf/db/local.d/locks")
    return success
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
        logging.debug(f"Error checking XDMCP: {e}")
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
    enabled_count = 0
    for daemon in daemons:
        success, output = run_command(daemon['cmd'])
        if success and "enabled" in output:
            enabled_count += 1
    return enabled_count == 1

def check_timesyncd_configured():
    success, _ = run_command("grep -E '^(NTP|FallbackNTP)=' /etc/systemd/timesyncd.conf")
    return success

def check_timesyncd_enabled_running():
    enabled, _ = run_command("systemctl is-enabled systemd-timesyncd | grep -w 'enabled'")
    active, _ = run_command("systemctl is-active systemd-timesyncd | grep -w 'active'")
    return enabled and active

def check_chrony_configured():
    success, _ = run_command("grep -E '^server ' /etc/chrony/chrony.conf")
    return success

def check_chrony_user():
    success, output = run_command("ps -eo user,comm | grep chronyd | grep -w '_chrony'")
    return success

def check_chrony_enabled_running():
    enabled, _ = run_command("systemctl is-enabled chronyd | grep -w 'enabled'")
    active, _ = run_command("systemctl is-active chronyd | grep -w 'active'")
    return enabled and active


def check_cron_enabled_running():
    enabled, _ = run_command("systemctl is-enabled cron | grep -w 'enabled'")
    active, _ = run_command("systemctl is-active cron | grep -w 'active'")
    return enabled and active

def check_crontab_restricted():
    return (not os.path.exists("/etc/cron.deny") and
            os.path.exists("/etc/cron.allow") and
            check_file_permissions("/etc/cron.allow", "600"))

def check_restricted_at_users():
    return (not os.path.exists("/etc/at.deny") and
            os.path.exists("/etc/at.allow") and
            check_file_permissions("/etc/at.allow", "600"))

def check_sshd_access_configured():
    success, _ = run_command(
        "grep -Ei '^(AllowUsers|DenyUsers|AllowGroups|DenyGroups)' /etc/ssh/sshd_config"
    )
    return success

def check_sshd_banner():
    success, _ = run_command("grep -E '^[^#]*Banner' /etc/ssh/sshd_config")
    return success

def check_sshd_ciphers():
    success, _ = run_command("grep -E '^[^#]*Ciphers' /etc/ssh/sshd_config")
    return success

def check_sshd_clientalive():
    interval_ok, _ = run_command("grep -E '^[^#]*ClientAliveInterval' /etc/ssh/sshd_config")
    countmax_ok, _ = run_command("grep -E '^[^#]*ClientAliveCountMax' /etc/ssh/sshd_config")
    return interval_ok and countmax_ok

def check_sshd_disable_forwarding():
    success, _ = run_command("grep -E '^[^#]*AllowTcpForwarding\\s+no' /etc/ssh/sshd_config")
    return success

def check_sshd_gssapiauth_disabled():
    success, _ = run_command("grep -E '^[^#]*GSSAPIAuthentication\\s+no' /etc/ssh/sshd_config")
    return success

def check_sshd_hostbasedauth_disabled():
    success, _ = run_command("grep -E '^[^#]*HostbasedAuthentication\\s+no' /etc/ssh/sshd_config")
    return success

def check_sshd_ignorerhosts_enabled():
    success, _ = run_command("grep -E '^[^#]*IgnoreRhosts\\s+yes' /etc/ssh/sshd_config")
    return success

def check_sshd_kexalgorithms():
    success, _ = run_command("grep -E '^[^#]*KexAlgorithms' /etc/ssh/sshd_config")
    return success

def check_sshd_logingracetime():
    success, _ = run_command("grep -E '^[^#]*LoginGraceTime' /etc/ssh/sshd_config")
    return success

def check_sshd_loglevel():
    success, _ = run_command("grep -E '^[^#]*LogLevel' /etc/ssh/sshd_config")
    return success

def check_sshd_macs():
    success, _ = run_command("grep -E '^[^#]*MACs' /etc/ssh/sshd_config")
    return success

def check_sshd_maxauthtries():
    success, _ = run_command("grep -E '^[^#]*MaxAuthTries' /etc/ssh/sshd_config")
    return success

def check_sshd_maxsessions():
    success, _ = run_command("grep -E '^[^#]*MaxSessions' /etc/ssh/sshd_config")
    return success

def check_sshd_maxstartups():
    success, _ = run_command("grep -E '^[^#]*MaxStartups' /etc/ssh/sshd_config")
    return success

def check_sshd_permitemptypasswords_disabled():
    success, _ = run_command("grep -E '^[^#]*PermitEmptyPasswords\\s+no' /etc/ssh/sshd_config")
    return success

def check_sshd_permitrootlogin_disabled():
    success, _ = run_command("grep -E '^[^#]*PermitRootLogin\\s+no' /etc/ssh/sshd_config")
    return success

def check_sshd_permituserenvironment_disabled():
    success, _ = run_command("grep -E '^[^#]*PermitUserEnvironment\\s+no' /etc/ssh/sshd_config")
    return success

def check_sshd_usepam_enabled():
    success, _ = run_command("grep -E '^[^#]*UsePAM\\s+yes' /etc/ssh/sshd_config")
    return success


import os
from shlex import quote

# --- SYSCTL checks ---

def check_sysctl_setting(param, expected):
    success, _ = run_command(f"sysctl {quote(param)} | grep -w {quote(expected)}")
    return success

def check_multiple_sysctl(params):
    return all(check_sysctl_setting(p, v) for p, v in params.items())

# --- Package checks ---

def check_package_installed(package):
    success, _ = run_command(f"dpkg-query -W {quote(package)}")
    return success

def check_package_not_installed(package):
    return not check_package_installed(package)

# --- SSH config checks ---

def check_sshd_config_setting(directive, value):
    # This matches uncommented lines with exact value
    cmd = (
        f"grep -E '^[ \\t]*{quote(directive)}[ \\t]+{quote(value)}[ \\t]*$' "
        "/etc/ssh/sshd_config | grep -v '^[ \\t]*#'"
    )
    success, _ = run_command(cmd)
    return success

def check_ssh_file_permissions(path, mode):
    return check_file_permissions(path, mode)

# --- UFW Firewall Checks ---

def check_ufw_enabled():
    success, _ = run_command("systemctl is-enabled ufw | grep -w 'enabled'")
    return success

def check_ufw_loopback():
    s1, _ = run_command("ufw status | grep 'Anywhere on lo'")
    s2, _ = run_command("ufw status | grep 'Anywhere DENY'")
    return s1 and s2

def check_ufw_default_deny():
    s1, _ = run_command("ufw status verbose | grep -i 'deny (incoming)'")
    s2, _ = run_command("ufw status verbose | grep -i 'deny (outgoing)'")
    s3, _ = run_command("ufw status verbose | grep -i 'deny (routed)'")
    return s1 and s2 and s3

# --- nftables ---

def check_nftables_table_exists():
    success, _ = run_command("nft list tables")
    return success

def check_nftables_service_enabled():
    success, _ = run_command("systemctl is-enabled nftables | grep -w 'enabled'")
    return success

# --- iptables (IPv4 and IPv6) ---

def check_iptables_default_deny(ipv6=False):
    cmd = "ip6tables" if ipv6 else "iptables"
    s1, _ = run_command(f"{cmd} -L INPUT | grep -w 'DROP'")
    s2, _ = run_command(f"{cmd} -L FORWARD | grep -w 'DROP'")
    s3, _ = run_command(f"{cmd} -L OUTPUT | grep -w 'DROP'")
    return s1 and s2 and s3

# --- sudo config ---

def check_sudo_installed():
    return check_package_installed("sudo")

def check_sudo_pty():
    success, _ = run_command("grep -Ei '^\\s*Defaults\\s+use_pty' /etc/sudoers")
    return success

def check_sudo_log_file():
    return os.path.exists("/var/log/sudo.log")     ###check this again

def check_sudo_authenticate_not_disabled():
    try:
        with open("/etc/sudoers") as f:
            return all("!authenticate" not in line or line.strip().startswith("#") or not line.strip().startswith("Defaults") for line in f)
    except Exception as e:
        logging.debug(f"Error reading /etc/sudoers: {e}")
        return False

def check_sudo_auth_timeout():
    try:
        with open("/etc/sudoers") as f:
            for line in f:
                if line.lstrip().startswith("Defaults") and "timestamp_timeout=" in line and not line.lstrip().startswith("#"):
                    try:
                        # Assuming timestamp_timeout is the first value after the equals sign
                        return int(line.split("timestamp_timeout=")[1].split()[0]) <= 15
                    except ValueError:
                        return False
        return False
    except Exception as e:
        logging.debug(f"Error reading /etc/sudoers: {e}")
        return False
def check_su_restricted():
    try:
        with open("/etc/pam.d/su") as f:
            return any("pam_wheel.so" in line and not line.strip().startswith("#") for line in f)
    except Exception as e:
        logging.debug(f"Error reading /etc/pam.d/su: {e}")
        return False

def check_pam_module_enabled(module, file, control):
    """
    Check if a specific PAM module with a given control type is enabled in a PAM config file.

    :param module: PAM module name (e.g., pam_unix.so)
    :param file: Full path to the PAM config file (e.g., /etc/pam.d/common-auth)
    :param control: Control flag (e.g., required, sufficient)
    :return: True if found, False otherwise
    """
    pattern = f"^\\s*{quote(control)}\\s+{quote(module)}"
    success, _ = run_command(f"grep -E {quote(pattern)} {quote(file)}")
    return success

def check_pam_faillock_option(option, file="/etc/pam.d/common-auth"):
    try:
        with open(file) as f:
            return any("pam_faillock.so" in line and option in line and not line.strip().startswith("#") for line in f)
    except Exception as e:
        logging.debug(f"Error reading {file}: {e}")
        return False
def check_pwquality_option(option, value=None, conf_file="/etc/security/pwquality.conf"):
    try:
        with open(conf_file) as f:
            for line in f:
                if line.lstrip().startswith("#"):
                    continue
                if value:
                    if f"{option}={value}" in line.replace(" ", ""):
                        return True
                elif option in line:
                    return True
        return False
    except Exception as e:
        logging.debug(f"Error reading {conf_file}: {e}")
        return False

def check_pwhistory_option(option, value=None, conf_file="/etc/security/pwhistory.conf"):
    try:
        with open(conf_file) as f:
            for line in f:
                if line.lstrip().startswith("#"):
                    continue
                if value and f"{option}={value}" in line.replace(" ", ""):
                    return True
                elif not value and option in line:
                    return True
        return False
    except Exception as e:
        logging.debug(f"Error reading {conf_file}: {e}")
        return False

def check_pam_pwhistory_use_authtok(file="/etc/pam.d/common-password"):
    try:
        with open(file) as f:
            return any("pam_pwhistory.so" in line and "use_authtok" in line and not line.lstrip().startswith("#") for line in f)
    except Exception as e:
        logging.debug(f"Error reading {file}: {e}")
        return False

def check_pam_unix_option(option=None, file="/etc/pam.d/common-password", must_exist=True):
    """
    Checks if pam_unix.so lines contain or exclude a specific option.
    Set `must_exist` to True to check presence, False for absence.
    If `option` is None, checks for strong hash algorithms.
    """
    try:
        with open(file, "r") as f:
            for line in f:
                if "pam_unix.so" in line and not line.strip().startswith("#"):
                    if option:
                        if (option in line) == must_exist:
                            return must_exist
                    elif any(alg in line for alg in ("sha512", "yescrypt")):
                        return True
        return False if option or not must_exist else True
    except Exception as e:
        logging.debug(f"Error reading {file}: {e}")
        return False

def check_login_defs_option(option):
    try:
        with open("/etc/login.defs") as f:
            return any(line.strip().startswith(option) for line in f if not line.strip().startswith("#"))
    except Exception as e:
        logging.debug(f"Error reading /etc/login.defs: {e}")
        return False

def check_shadow_option_for_all_users(field_index, min_value=1):
    try:
        with open("/etc/shadow") as f:
            for line in f:
                if line.startswith("#") or line.startswith("root:!*:"):
                    continue
                fields = line.strip().split(":")
                if len(fields) <= field_index or not fields[field_index] or \
                   (fields[field_index].isdigit() and int(fields[field_index]) < min_value):
                    return False
        return True
    except Exception as e:
        logging.debug(f"Error reading /etc/shadow: {e}")
        return False

def check_shadow_last_change_in_past():
    today = int(time.time() // 86400)
    try:
        with open("/etc/shadow") as f:
            return all(int(f.split(":")[2]) <= today for f in f if not f.startswith("#") and f.split(":")[2].isdigit())
    except Exception as e:
        logging.debug(f"Error reading /etc/shadow: {e}")
        return False

def check_login_defs_hash_algorithm():
    try:
        with open("/etc/login.defs") as f:
            return any("ENCRYPT_METHOD" in line and any(alg in line for alg in ("SHA512", "YESCRYPT"))
                       for line in f if not line.strip().startswith("#"))
    except Exception as e:
        logging.debug(f"Error reading /etc/login.defs: {e}")
        return False

def check_only_root_uid0():
    """Ensure only 'root' has UID 0 in /etc/passwd."""
    try:
        with open("/etc/passwd") as f:
            uid0_users = [line.split(":")[0] for line in f if line.strip().split(":")[2] == "0"]
        return uid0_users == ["root"]
    except Exception as e:
        logging.debug(f"Error reading /etc/passwd: {e}")
        return False

def check_only_root_gid0():
    """Ensure only root has GID 0."""
    try:
        with open("/etc/passwd") as f:
            return [line.split(":")[0] for line in f if line.split(":")[3] == "0"] == ["root"]
    except Exception as e:
        logging.debug(f"Error reading /etc/passwd: {e}")
        return False

def check_only_group_root_gid0():
    """Ensure only group 'root' has GID 0."""
    try:
        with open("/etc/group") as f:
            return [line.split(":")[0] for line in f if line.split(":")[2] == "0"] == ["root"]
    except Exception as e:
        logging.debug(f"Error reading /etc/group: {e}")
        return False

def check_root_account_access_controlled():
    """Ensure root account is locked or has a password set."""
    try:
        with open("/etc/shadow") as f:
            for line in f:
                if line.startswith("root:"):
                    return line.split(":")[1] not in ["*", "!", "!!", ""]
        return False
    except Exception as e:
        logging.debug(f"Error reading /etc/shadow: {e}")
        return False

def check_root_path_integrity():
    """Ensure root's PATH does not include insecure entries."""
    insecure = {"", ".", "..", "/tmp", "/var/tmp"}
    try:
        with open("/etc/profile") as f:
            for line in f:
                if "PATH=" in line and "root" in line:
                    path_dirs = re.search(r'PATH=(.*)', line)
                    if path_dirs:
                        if any(d in insecure for d in path_dirs.group(1).split(":")):
                            return False
        return True
    except Exception as e:
        logging.debug(f"Error reading /etc/profile: {e}")
        return False

def check_root_umask():
    """Ensure root user umask is set."""
    try:
        for file in ["/root/.profile", "/etc/profile"]:
            if os.path.exists(file):
                with open(file) as f:
                    if any("umask" in line and not line.strip().startswith("#") for line in f):
                        return True
        return False
    except Exception as e:
        logging.debug(f"Error reading umask files: {e}")
        return False

def check_system_accounts_no_login_shell():
    """Ensure system accounts do not have a valid login shell."""
    try:
        with open("/etc/passwd") as f:
            return all(
                shell in ["/usr/sbin/nologin", "/bin/false"]
                for line in f
                if 0 < int(parts := line.strip().split(":"))[2] < 1000
                for shell in [parts[-1]]
            )
    except Exception as e:
        logging.debug(f"Error reading /etc/passwd: {e}")
        return False

def check_accounts_without_login_shell_locked():
    """Ensure accounts without a valid login shell are locked."""
    try:
        with open("/etc/passwd") as f:
            no_login_users = {line.split(":")[0] for line in f if line.strip().split(":")[-1] in ["/usr/sbin/nologin", "/bin/false"]}
        with open("/etc/shadow") as f:
            return all(
                line.split(":")[1] in ["*", "!", "!!"]
                for line in f
                if line.split(":")[0] in no_login_users
            )
    except Exception as e:
        logging.debug(f"Error reading /etc/shadow: {e}")
        return False
def check_nologin_not_in_shells():
    """Ensure nologin is not listed in /etc/shells."""
    try:
        with open("/etc/shells", "r") as f:
            for line in f:
                if "nologin" in line and not line.strip().startswith("#"):
                    return False
        return True
    except Exception as e:
        logging.debug(f"Error reading /etc/shells: {e}")
        return False

def check_default_shell_timeout():
    """Ensure default user shell timeout is configured (TMOUT in /etc/profile or /etc/bash.bashrc)."""
    try:
        for file in ["/etc/profile", "/etc/bash.bashrc"]:
            if os.path.exists(file):
                with open(file, "r") as f:
                    for line in f:
                        if "TMOUT" in line and not line.strip().startswith("#"):
                            return True
        return False
    except Exception as e:
        logging.debug(f"Error reading shell timeout files: {e}")
        return False

def check_default_user_umask():
    """Ensure default user umask is configured in /etc/profile or /etc/bash.bashrc."""
    try:
        for file in ["/etc/profile", "/etc/bash.bashrc"]:
            if os.path.exists(file):
                with open(file, "r") as f:
                    for line in f:
                        if "umask" in line and not line.strip().startswith("#"):
                            return True
        return False
    except Exception as e:
        logging.debug(f"Error reading umask files: {e}")
        return False

# --- AIDE and Integrity Checking ---

def check_package_installed(package):
    success, _ = run_command(f"dpkg-query -W {quote(package)}")
    return success

def check_aide_installed():
    return check_package_installed("aide")

def check_aide_cron():
    success, _ = run_command("crontab -u root -l | grep aide")
    return success

def check_file_integrity():
    return os.path.exists("/var/lib/aide/aide.db")

# --- Service Checks ---

def check_service_enabled_active(service):
    """Check if a service is both enabled and active."""
    enabled, _ = run_command(f"systemctl is-enabled {quote(service)} | grep -w 'enabled'")
    active, _ = run_command(f"systemctl is-active {quote(service)} | grep -w 'active'")
    return enabled and active

def check_service_not_active(service):
    """Check if a service is inactive."""
    success, _ = run_command(f"systemctl is-active {quote(service)} | grep -w 'inactive'")
    return success

# --- journald Configuration ---

def check_journald_config(option, expected_value):
    """Check if a specific journald config option matches the expected value."""
    try:
        with open("/etc/systemd/journald.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if line.startswith(option):
                    key, _, value = line.partition("=")
                    return value.strip() == expected_value
        return False
    except Exception as e:
        logging.debug(f"Error reading journald.conf: {e}")
        return False

def check_only_one_logging_system():
    """Ensure only one logging system (journald or rsyslog) is enabled."""
    journald, _ = run_command("systemctl is-enabled systemd-journald | grep -w 'enabled'")
    rsyslog, _ = run_command("systemctl is-enabled rsyslog | grep -w 'enabled'")
    return (journald and not rsyslog) or (not journald and rsyslog)

def check_logfile_permissions():
    """Check that all files in /var/log are 0640 or stricter."""
    try:
        for root, dirs, files in os.walk("/var/log"):
            for name in files:
                path = os.path.join(root, name)
                if os.path.isfile(path):
                    mode = oct(os.stat(path).st_mode)[-3:]
                    if int(mode) > 640:
                        return False
        return True
    except Exception as e:
        logging.debug(f"Error checking log file permissions: {e}")
        return False

def check_rsyslog_log_file_creation_mode():
    """Check rsyslog $FileCreateMode is set to 0640 or stricter."""
    try:
        with open("/etc/rsyslog.conf") as f:
            for line in f:
                if "$FileCreateMode" in line and not line.strip().startswith("#"):
                    mode = line.split()[-1]
                    return int(mode, 8) <= 0o640
        return False
    except Exception as e:
        logging.debug(f"Error reading /etc/rsyslog.conf: {e}")
        return False

def check_rsyslog_not_receive_remote():
    """Check rsyslog is not configured to receive logs from remote clients."""
    try:
        with open("/etc/rsyslog.conf") as f:
            for line in f:
                if "ModLoad imudp" in line or "ModLoad imtcp" in line:
                    return False
        return True
    except Exception as e:
        logging.debug(f"Error reading /etc/rsyslog.conf: {e}")
        return False
### 7.1 System File Permissions

def check_no_world_writable_files():
    """Ensure no world-writable files exist on the filesystem."""
    success, output = run_command("find / -xdev -type f -perm -0002 2>/dev/null")
    return output.strip() == ""


def check_no_unowned_files():
    """Ensure there are no unowned or ungrouped files (7.1.12)."""
    success, output = run_command("find / -xdev \\( -nouser -o -nogroup \\) 2>/dev/null")
    return output.strip() == ""


### 7.2 Local User and Group Settings

def check_shadowed_passwords():
    """Ensure accounts in /etc/passwd use shadowed passwords (7.2.1)."""
    # PASS if awk returns no output (i.e., not success and output is empty)
    success, _ = run_command("awk -F: '($2 != \"x\") {print}' /etc/passwd")
    return not success

def check_no_empty_passwords():
    """Ensure no empty password fields exist in /etc/shadow (7.2.2)."""
    # PASS if awk returns no output (i.e., not success and output is empty)
    success, _ = run_command("awk -F: '($2 == \"\") {print}' /etc/shadow")
    return not success

def check_all_passwd_groups_exist():
    """Ensure all groups referenced in /etc/passwd exist in /etc/group (7.2.3)."""
    # PASS if shell pipeline returns success (exit 0)
    success, _ = run_command(
        "awk -F: '{print $4}' /etc/passwd | while read gid; do getent group \"$gid\" >/dev/null || exit 1; done"
    )
    return success

def check_shadow_group_empty():
    """Ensure shadow group is empty (7.2.4)."""
    # PASS if grep returns no output (i.e., not success and output is empty)
    success, _ = run_command("awk -F: '/^shadow/ {print $4}' /etc/group | grep -vq '^$'")
    return not success

def check_no_duplicate_uids():
    """Ensure no duplicate UIDs exist (7.2.5)."""
    # PASS if cut/sort/uniq returns no output (i.e., not success and output is empty)
    success, _ = run_command("cut -d: -f3 /etc/passwd | sort | uniq -d")
    duplicates = _.strip()
    if duplicates:
        print("Duplicate usernames found:", duplicates)
        return False
    return True

def check_no_duplicate_usernames():
    """Ensure no duplicate user names exist (7.2.7)."""
    success, output = run_command("cut -d: -f1 /etc/passwd | sort | uniq -d")
    duplicates = output.strip()
    if duplicates:
        print("Duplicate usernames found:", duplicates)
        return False
    return True

def check_no_duplicate_groupnames():
    """Ensure no duplicate group names exist (7.2.8)."""
    success, output = run_command("cut -d: -f1 /etc/group | sort | uniq -d")
    duplicates = output.strip()
    if duplicates:
        print("Duplicate usernames found:", duplicates)
        return False
    return True

def check_user_home_directories_exist():
    """Ensure local interactive user home directories exist."""
    success, output = run_command(
        "awk -F: '($3 >= 1000 && $1 != \"nobody\") {if ($6 == \"\" || system(\"[ -d \" $6 \" ]\")) exit 1}' /etc/passwd"
    )
    if not success:
        print("One or more user home directories are missing or invalid.")
    return success


def check_dot_files_permissions():
    """Ensure local interactive user dot files access is configured (not group/world writable)."""
    success, output = run_command("find /home -xdev -type f -name '.*' -perm /022")
    violations = output.strip()
    if violations:
        print("Insecure dotfiles found:\n", violations)
        return False
    return True



### Dispatcher Function
def check_dispatcher(benchmark):
    check_functions = {
        # General Utility
        "file_exists": lambda b: check_file_exists(b["path"]),
        # 7.1 System File Permissions
        "no_world_writable_files": lambda _: check_no_world_writable_files(),
        "no_unowned_files": lambda _: check_no_unowned_files(),
        "suid_sgid_file_list": lambda _: check_suid_sgid_file_list(), # For 7.1.13
        # 7.2 Local User and Group Settings
        "shadowed_passwords": lambda _: check_shadowed_passwords(),
        "no_empty_passwords": lambda _: check_no_empty_passwords(),
        "all_passwd_groups_exist": lambda _: check_all_passwd_groups_exist(),
        "shadow_group_empty": lambda _: check_shadow_group_empty(),
        "no_duplicate_uids": lambda _: check_no_duplicate_uids(),
        "no_duplicate_usernames": lambda _: check_no_duplicate_usernames(),
        "no_duplicate_groupnames": lambda _: check_no_duplicate_groupnames(),
        "user_home_directories_exist": lambda _: check_user_home_directories_exist(),
        "dot_files_permissions": lambda _: check_dot_files_permissions(),
        "manual": lambda _: False,
        # Rest of the checks
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
        "sudo_log_file": lambda _: check_sudo_log_file(),
        "sudo_authenticate_not_disabled": lambda _: check_sudo_authenticate_not_disabled(),
        "sudo_auth_timeout": lambda _: check_sudo_auth_timeout(),
        "su_restricted": lambda _: check_su_restricted(),
        "pam_module_enabled": lambda b: check_pam_module_enabled(b["module"], b["file"], b["control"]),
        "pam_faillock_option": lambda b: check_pam_faillock_option(b["option"], b.get("file", "/etc/pam.d/common-auth")),
        "pwquality_option": lambda b: check_pwquality_option(b["option"], b.get("value"), b.get("conf_file", "/etc/security/pwquality.conf")),
        "pwhistory_option": lambda b: check_pwhistory_option(b["option"], b.get("value"), b.get("conf_file", "/etc/security/pwhistory.conf")),
        "pam_pwhistory_use_authtok": lambda b: check_pam_pwhistory_use_authtok(b.get("file", "/etc/pam.d/common-password")),
        "pam_unix_option_absent": lambda b: check_pam_unix_option(option=b["option"],file=b.get("file","/etc/pam.d/common-password"),must_exist=False),
        "pam_unix_option_present":lambda b:check_pam_unix_option(option=b["option"],file=b.get("file","/etc/pam.d/common-password"),must_exist=True),
        "pam_unix_strong_hash": lambda b: check_pam_unix_option(file=b.get("file","/etc/pam.d/common-password"),option=None ),
        "login_defs_option": lambda b: check_login_defs_option(b["option"]),
        "shadow_option_for_all_users": lambda b: check_shadow_option_for_all_users(b["field_index"], b.get("min_value", 1)),
        "shadow_last_change_in_past": lambda _: check_shadow_last_change_in_past(),
        "login_defs_hash_algorithm": lambda _: check_login_defs_hash_algorithm(),
        "aide_installed": lambda _: check_aide_installed(),
        "aide_cron": lambda _: check_aide_cron(),
        "file_integrity": lambda _: check_file_integrity(),
        "only_root_uid0": lambda _: check_only_root_uid0(),
        "only_root_gid0": lambda _: check_only_root_gid0(),
        "only_group_root_gid0": lambda _: check_only_group_root_gid0(),
        "root_account_access_controlled": lambda _: check_root_account_access_controlled(),
        "root_path_integrity": lambda _: check_root_path_integrity(),
        "root_umask": lambda _: check_root_umask(),
        "system_accounts_no_login_shell": lambda _: check_system_accounts_no_login_shell(),
        "accounts_without_login_shell_locked": lambda _: check_accounts_without_login_shell_locked(),
        "nologin_not_in_shells": lambda _: check_nologin_not_in_shells(),
        "default_shell_timeout": lambda _: check_default_shell_timeout(),
        "default_user_umask": lambda _: check_default_user_umask(),
        "service_enabled_active": lambda b: check_service_enabled_active(b["service"]),
        "service_not_active": lambda b: check_service_not_active(b["service"]),
        "journald_config": lambda b: check_journald_config(b["option"], b["expected_value"]),
        "only_one_logging_system": lambda _: check_only_one_logging_system(),
        "logfile_permissions": lambda _: check_logfile_permissions(),
        "rsyslog_log_file_creation_mode": lambda _: check_rsyslog_log_file_creation_mode(),
        "rsyslog_not_receive_remote": lambda _: check_rsyslog_not_receive_remote(),
        "no_unowned_files": lambda _: check_no_unowned_files(),
        "no_duplicate_uids": lambda _: check_no_duplicate_uids(),
        "no_duplicate_usernames": lambda _: check_no_duplicate_usernames(),
        "no_duplicate_groupnames": lambda _: check_no_duplicate_groupnames(),
        "no_world_writable_files": lambda _: check_no_world_writable_files(),
        "shadowed_passwords": lambda _: check_shadowed_passwords(),
        "no_empty_passwords": lambda _: check_no_empty_passwords(),
        "all_passwd_groups_exist": lambda _: check_all_passwd_groups_exist(),
        "shadow_group_empty": lambda _: check_shadow_group_empty(),
    }

    check_func = check_functions.get(benchmark["type"])
    
    # Special handling for SUID/SGID manual check (7.1.13)
    if benchmark["id"] == "7.1.13":
        # Run the list function but mark as MANUAL
        check_suid_sgid_file_list() 
        return False # Always returns False to mark as MANUAL/Needs Review

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
        # Use explicit check for 7.1.13 to ensure it's MANUAL
        if benchmark["id"] == "7.1.13":
             status_str = "MANUAL"
        else:
             status_str = "MANUAL" if benchmark["type"] == "manual" else "PASS" if status else "FAIL"
        
        result_str = f"{benchmark['id']}: {status_str} - {benchmark['description']}"
        # commenting this line to avoid double output:
        # logging.info(result_str)
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
