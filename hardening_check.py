#!/usr/bin/python3

import os, sys, subprocess, shutil

def cleanup():
    print("Exiting...")
    sys.exit()

def write_line_to_err_file(line):
    # opening the outfile
    fp = open('errors.txt', 'a+')
    fp.write(line+"\n")
    fp.close()


def prompt_sudo():
    if os.geteuid() != 0:
        print("This script requires root privileges, please rerun the script with sudo or as root")
        cleanup()

def check_sudo():
    if shutil.which('sudo') is None:
        write_line_to_err_file("Sudo not set")

def check_root_disable():
    if "L" not in subprocess.check_output(['passwd','-S','root']).decode("utf-8"):
        write_line_to_err_file("Root account not locked")

def check_nfs_purge():
    nfs = "nfs-kernel-server nfs-common portmap rpcbind autofs".split(' ')
    for pkg in nfs:
        try:
            out = subprocess.check_output(['dpkg','-s', pkg]).decode("utf-8")
            if "Status: install ok" in out:
                write_line_to_err_file(f'package {pkg} is installed, should be purged.')
        except:
            continue

def check_firewall():
    if shutil.which('ufw') is None:
        write_line_to_err_file("ufw not set")

def check_ssh_brute():
    out = subprocess.check_output(['ufw','status', 'numbered']).decode("utf-8")
    if "LIMIT" not in out:
        write_line_to_err_file("ssh is not rate-limited")

def check_acct():
    try:
        subprocess.check_output(['dpkg','-s', "acct"])
    except:
        write_line_to_err_file("acct not installed")

def check_unattended_upg():
    try:
        os.path.isfile("/etc/apt/apt.conf.d/20auto-upgrades")
    except:
        write_line_to_err_file("Unattended upgrades not installed/enabled")

def check_disable_avahi():
    try:
        if "active" in subprocess.check_output(['service', 'avahi-daemon' ,'status']).decode("utf-8"):
            write_line_to_err_file("avahi daemon is enabled")
    except subprocess.CalledProcessError:
        print("!!!WARNING!!!: exim is probably not installed, continuing....")
        write_line_to_err_file("avahi is not installed")

def check_disable_exim_pckgs():
    try:
        if "active" in subprocess.check_output(['service', 'exim4' ,'status']).decode("utf-8"):
            write_line_to_err_file("exim is enabled")
    except subprocess.CalledProcessError:
        print("!!!WARNING!!!: exim is probably not installed, continuing....")
        write_line_to_err_file("exim is not installed")



def check_disabled_compilers():
    compilers = ['/usr/bin/cc','/usr/bin/gcc']
    for compiler in compilers:
        val = os.access(compiler, os.R_OK) # Check for read access
        val = os.access(compiler, os.W_OK) # Check for write access
        val = os.access(compiler, os.X_OK) # Check for execution access
        val = os.access(compiler, os.F_OK) # Check for existence of file
        print(val)
        if val:
            write_line_to_err_file(f"{compiler} does not have proper permissions") 

def check_kernel_tuning():
    tunes = [
    "kernel.randomize_va_space=1", 
    "net.ipv4.conf.all.rp_filter=1", 
    "net.ipv4.conf.all.accept_source_route=0",
    "net.ipv4.icmp_echo_ignore_broadcasts=1",
    "net.ipv4.conf.all.log_martians=1",
    "net.ipv4.conf.default.log_martians=1",
    "net.ipv4.conf.all.accept_redirects=0",
    "net.ipv6.conf.all.accept_redirects=0",
    "net.ipv4.conf.all.send_redirects=0",
    "kernel.sysrq=0",
    "net.ipv4.tcp_timestamps=0",
    "net.ipv4.tcp_syncookies=1",
    "net.ipv4.icmp_ignore_bogus_error_responses=1"]
    with open('/etc/sysctl.conf') as f:
        for param in tunes:
            if param not in f.read():
                continue
            else:
                write_line_to_err_file(f"KERNEL {param} missing")

def check_sshd_config_backup():
    pwd = os.getcwd()
    if not os.path.isfile(pwd + "/sshd_config"):
         write_line_to_err_file("SSHd config has not been backed up to cwd")

def check_ssh_tuning():
    tunes = [
    "Protocol 2",
    "PermitRootLogin no",
    "MaxAuthTries 3",
    "PermitEmptyPasswords no",
    "LoginGraceTime 60",
    "IgnoreRhosts yes"
    ]
    sshd_conf="/etc/ssh/sshd_config"
    with open(sshd_conf) as f:
        for param in tunes:
            if param not in f.read():
                continue
            else:
                write_line_to_err_file(f"SSH {param} missing")

def check_warning_banner():
    motd="/etc/ssh/sshd_banner"
    with open(motd) as f:
        if "Unauthorized access to this system" not in f.read():
                write_line_to_err_file("warning banner not set")

def main():
    # starts from fresh error file
    if os.path.exists("errors.txt"):
        os.remove("errors.txt")

    bold = "\033[1m" 
    end = "\033[0m"


    try:
        prompt_sudo()
        print(bold+bold+"Check for purged nfs"+end)
        check_nfs_purge()
        print(bold+"Check firewall rules"+end)
        check_firewall()
        print(bold+"Check for SSH rate limiting"+end)
        check_ssh_brute()
        print(bold+"Check for unattended upgrades"+end)
        check_unattended_upg()
        print(bold+"Check is avahi daemon is enabled"+end)
        check_disable_avahi()
        print(bold+"Check if exim is enabled"+end)
        check_disable_exim_pckgs()
        print(bold+"check if accounting is present"+end)
        check_acct()
        print(bold+"check if compilers are disabled"+end)
        check_disabled_compilers()
        print(bold+"check for kernel parameter tuning"+end)
        check_kernel_tuning()
        print(bold+"check if SSHd config has been properly backed up"+end)
        check_sshd_config_backup()
        print(bold+"check that SSHd is properly configured"+end)
        check_ssh_tuning()
        print(bold+"check for correct SSH warning banner"+end)
        check_warning_banner()
        print(bold+"Check for sudo"+end)
        check_sudo()
        print(bold+"Checking for disabled root"+end)
        check_root_disable()
    except KeyboardInterrupt:
        print(bold+"Exiting..."+end)
        sys.exit()

if __name__ == "__main__":
    main()