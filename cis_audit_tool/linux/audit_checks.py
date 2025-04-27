import subprocess
from .benchmarks import LINUX_BENCHMARKS

### Helper function to run shell commands
def run_command(cmd):
    """Runs a shell command and returns True if successful, False otherwise."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"Error executing command {cmd}: {e}")
        return False


### Check if a kernel module is disabled
def check_kernel_module_disabled(module):
    return not run_command(f"lsmod | grep -w {module}")


### Check if a partition is mounted separately
def check_partition_mounted(partition):
    return run_command(f"mount | grep -w {partition}")


### Check if a partition has a specific mount option (nodev, nosuid, noexec)
def check_partition_option(partition, option):
    return run_command(f"mount | grep -w {partition} | grep -w {option}")


### Check if AppArmor is installed and enabled
def check_apparmor_installed():
    return run_command("dpkg-query -W apparmor")


def check_apparmor_enabled():
    return run_command("apparmor_status | grep 'enabled'")


def check_apparmor_enforce():
    return run_command("apparmor_status | grep 'enforce'")


### Bootloader security checks
def check_bootloader_password():
    return run_command("grep 'password' /boot/grub/grub.cfg")


def check_bootloader_permissions():
    return run_command("stat -c %a /boot/grub/grub.cfg | grep '600'")


### Process Hardening checks
def check_aslr_enabled():
    return run_command("sysctl kernel.randomize_va_space | grep '2'")


def check_ptrace_scope():
    return run_command("sysctl kernel.yama.ptrace_scope | grep '1'")


def check_coredumps_restricted():
    return run_command("grep 'fs.suid_dumpable=0' /etc/sysctl.conf")


def check_prelink_not_installed():
    return not run_command("dpkg-query -W prelink")


def check_auto_error_reporting_disabled():
    return run_command("systemctl is-enabled apport | grep 'disabled'")


### Login Banner & Access Checks
def check_motd_access():
    return run_command("stat -c %a /etc/motd | grep '644'")


def check_issue_access():
    return run_command("stat -c %a /etc/issue | grep '644'")


def check_issue_net_access():
    return run_command("stat -c %a /etc/issue.net | grep '644'")


### GDM Configuration Checks
def check_gdm_config(setting, expected_value):
    return run_command(f"gsettings get org.gnome.login-screen {setting} | grep '{expected_value}'")


### Service Checks
def check_service_disabled(service):
    return run_command(f"systemctl is-enabled {service} | grep 'disabled'")


def check_service_not_installed(service):
    return not run_command(f"dpkg-query -W {service}")


### Time Synchronization Checks
def check_timesync_configured():
    return run_command("timedatectl show | grep 'NTP=yes'")


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
        "issue_access": lambda _: check_issue_access(),
        "issue_net_access": lambda _: check_issue_net_access(),
        "gdm_config": lambda b: check_gdm_config(b["setting"], b["expected_value"]),
        "service_disabled": lambda b: check_service_disabled(b["service"]),
        "service_not_installed": lambda b: check_service_not_installed(b["service"]),
        "timesync_configured": lambda _: check_timesync_configured(),
    }

    check_func = check_functions.get(benchmark["type"])
    if check_func:
        return check_func(benchmark)
    # else:
    #     print(f"Unknown benchmark type: {benchmark['type']}")
    #     return False


### Run Audit Function
def run_linux_audit(config, level=None, includes=None, excludes=None):
    results = []
    for benchmark in LINUX_BENCHMARKS:
        if (level and benchmark["level"] != level) or \
           (includes and benchmark["id"] not in includes) or \
           (excludes and benchmark["id"] in excludes):
            continue

        status = check_dispatcher(benchmark)

        status_str = "MANUAL" if benchmark["type"] == "manual" else "PASS" if status else "FAIL"
        result_str = f"{benchmark['id']}: {status_str} - {benchmark['description']}"
        
        print(result_str)  # Print each result in the desired format

        results.append({
            "id": benchmark["id"],
            "status": status_str,
            "description": benchmark["description"]
        })

    return results
