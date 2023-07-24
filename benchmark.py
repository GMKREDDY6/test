import subprocess
import shlex
import os
import json
import glob

security_limits_files = ['/etc/security/limits.conf'] + glob.glob('/etc/security/limits.d/*')
sysctl_files = ["/etc/sysctl.conf"] + glob.glob('/etc/sysctl.d/*')
cron_files = glob.glob('/etc/cron.*') + ['/etc/crontab']
sudoer_files = ['/etc/sudoers'] + glob.glob('/etc/sudoers.d')
rsyslog_files = ['/etc/rsyslog.conf'] + glob.glob("/etc/rsyslog.d/*.conf")
logrotate_files = ['/etc/logrotate.conf'] + glob.glob("/etc/logrotate.d/*")
inetd_files = glob.glob("/etc/inetd.*")

inetd_dict = {'chargen services are': 'chargen', "daytime services are": 'daytime',
              'discard services are': 'discard', 'echo services are': 'echo',
              "time services are": 'time', 'rsh server is': ['shell', 'login', 'exec'],
              'talk server is': ['talk', 'ntalk'], 'telnet server is': 'telnet',
              'tftp server is': 'tftp'}

ssh_dict = {"SSH Protocol is set to 2": "^Protocol",
            "SSH LogLevel is set to INFO": "^LogLevel",
            "SSH X11 forwarding is disabled": "^X11Forwarding",
            "SSH MaxAuthTries is set to 4 or less": "^MaxAuthTries",
            "SSH IgnoreRhosts is enabled": "^IgnoreRhosts",
            "SSH HostbasedAuthentication is disabled": "^HostbasedAuthentication",
            "SSH root login is disabled": "^PermitRootLogin",
            "SSH PermitEmptyPasswords is disabled": "^PermitEmptyPasswords",
            "SSH PermitUserEnvironment is disabled": "^PermitUserEnvironment",
            "only approved MAC algorithms are used": "^MACs",
            "SSH Idle Timeout Interval is configured": ["^ClientAliveInterval","^ClientAliveCountMax"],
            "SSH LoginGraceTime is set to one minute or less": "^LoginGraceTime",
            "SSH access is limited": ["^AllowUsers", "^AllowGroups", "^DenyUsers", "^DenyGroups"],
            "SSH warning banner is configured": "^Banner",
            "SSH PAM is enabled": 'UsePam',
            "SSH AllowTcpForwarding is disabled": "AllowTcpForwarding",
            "SSH MaxStartups is configured": "maxstartups",
            "SSH MaxSessions is set to 4 or less": "MaxSessions"
            }
audit_dict = {"events that modify date and time information are collected": "time-change",
              "events that modify user/group information are collected": 'identity',
              "events that modify the system's network environment are collected": "system-locale",
              "events that modify the system's Mandatory Access Controls are collected": "MAC-policy",
              "login and logout events are collected": "logins",
              "session initiation information is collected": "session",
              "discretionary access control permission modification events are collected": "perm_mod",
              "unsuccessful unauthorized file access attempts are collected": "access",
              "successful file system mounts are collected": "mounts",
              "file deletion events by users are collected": "delete",
              "changes to system administration scope (sudoers) is collected": "scope",
              "system administrator actions (sudolog) are collected": "actions",
              "kernel module loading and unloading is collected": "modules"}

usr_grp_files = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow',
                 '/etc/passwd-', '/etc/shadow-', '/etc/group-', '/etc/gshadow-',]

bootloader_permissions = """#!/bin/bash
tst1="" tst2="" tst3="" tst4="" test1="" test2="" efidir="" gbdir="" grubdir="" grubfile="" userfile=""
efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT')
gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*')
for file in "$efidir"/grub.cfg "$efidir"/grub.conf; do
 [ -f "$file" ] && grubdir="$efidir" && grubfile=$file
done
if [ -z "$grubdir" ]; then
 for file in "$gbdir"/grub.cfg "$gbdir"/grub.conf; do
 [ -f "$file" ] && grubdir="$gbdir" && grubfile=$file
 done
fi
userfile="$grubdir/user.cfg"
stat -c "%a" "$grubfile" | grep -Pq '^\h*[0-7]00$' && tst1=pass
output="Permissions on \"$grubfile\" are \"$(stat -c "%a" "$grubfile")\""
stat -c "%u:%g" "$grubfile" | grep -Pq '^\h*0:0$' && tst2=pass
output2="\"$grubfile\" is owned by \"$(stat -c "%U" "$grubfile")\" and
belongs to group \"$(stat -c "%G" "$grubfile")\""
[ "$tst1" = pass ] && [ "$tst2" = pass ] && test1=pass
if [ -f "$userfile" ]; then
 stat -c "%a" "$userfile" | grep -Pq '^\h*[0-7]00$' && tst3=pass
 output3="Permissions on \"$userfile\" are \"$(stat -c "%a" "$userfile")\""
 stat -c "%u:%g" "$userfile" | grep -Pq '^\h*0:0$' && tst4=pass
 output4="\"$userfile\" is owned by \"$(stat -c "%U" "$userfile")\" and
belongs to group \"$(stat -c "%G" "$userfile")\""
 [ "$tst3" = pass ] && [ "$tst4" = pass ] && test2=pass
else
 test2=pass
fi
[ "$test1" = pass ] && [ "$test2" = pass ] && passing=true
# If passing is true we pass
if [ "$passing" = true ] ; then
 echo "PASSED:"
 echo "$output"
 echo "$output2"
 [ -n "$output3" ] && echo "$output3"
 [ -n "$output4" ] && echo "$output4"
else
 # print the reason why we are failing
 echo "FAILED:"
 echo "$output"
 echo "$output2"
 [ -n "$output3" ] && echo "$output3"
 [ -n "$output4" ] && echo "$output4"
fi"""

bootloader_passwd = """#!/bin/bash
tst1="" tst2="" output=""
efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT')
gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*')
if [ -f "$efidir"/grub.cfg ]; then
 grubdir="$efidir" && grubfile="$efidir/grub.cfg"
elif [ -f "$gbdir"/grub.cfg ]; then
 grubdir="$gbdir" && grubfile="$gbdir/grub.cfg"
fi
userfile="$grubdir/user.cfg"
[ -f "$userfile" ] && grep -Pq '^\h*GRUB2_PASSWORD\h*=\h*.+$' "$userfile" && output="\n PASSED: bootloader password set in \"$userfile\"\n\n"
if [ -z "$output" ] && [ -f "$grubfile" ]; then
 grep -Piq '^\h*set\h+superusers\h*=\h*"?[^"\n\r]+"?(\h+.*)?$' "$grubfile" && tst1=pass
 grep -Piq '^\h*password\h+\H+\h+.+$' "$grubfile" && tst2=pass
 [ "$tst1" = pass ] && [ "$tst2" = pass ] && output="\n\n*** PASSED: bootloader password set in \"$grubfile\" ***\n\n"
fi
[ -n "$output" ] && echo -e "$output" || echo -e '\n\n *** FAILED: bootloader password is not set ***\n\n'"""

ipv6_disable = """#!/bin/bash
output=""
efidir=$(find /boot/efi/EFI/* -type d -not -name 'BOOT')
gbdir=$(find /boot -maxdepth 1 -type d -name 'grub*')
[ -f "$efidir"/grubenv ] && grubfile="$efidir/grubenv" || grubfile="$gbdir/grubenv"
! grep "^\s*kernelopts=" "$grubfile" | grep -vq ipv6.disable=1 &&
output="ipv6 disabled in grub config"
if grep -Eqs "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf && grep -Eqs "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf && sysctl net.ipv6.conf.all.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*" && sysctl net.ipv6.conf.default.disable_ipv6 | grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*"; then
 [ -n "$output" ] && output="$output, and in sysctl config" || output="ipv6 disabled in sysctl config"
fi
[ -n "$output" ] && echo -e "$output" || echo -e " IPv6 is enabled on the system"
"""

user_shell_tmout = """#!/bin/bash
output1="" output2=""
[ -f /etc/bashrc ] && BRC="/etc/bashrc"
for f in "$BRC" /etc/profile /etc/profile.d/*.sh ; do
 grep -Pq '^\s*([^#]+\s+)?TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' "$f" && grep -Pq '^\s*([^#]+;\s*)?readonly\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && grep -Pq '^\s*([^#]+;\s*)?export\s+TMOUT(\s+|\s*;|\s*$|=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9]))\b' "$f" && output1="$f"
done
grep -Pq '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh "$BRC" && output2=$(grep -Ps '^\s*([^#]+\s+)?TMOUT=(9[0-9][1-9]|9[1-9][0-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh $BRC)
if [ -n "$output1" ] && [ -z "$output2" ]; then
 echo -e "\nPASSED\n\nTMOUT is configured in: \"$output1\"\n"
else
 [ -z "$output1" ] && echo -e "\nFAILED\n\nTMOUT is not configured\n"
 [ -n "$output2" ] && echo -e "\nFAILED\n\nTMOUT is incorrectly configured
in: \"$output2\"\n"
fi"""

root_path_integrity_script = """#!/bin/bash
if [ "`echo $PATH | grep :: `" != "" ]; then
 echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | grep :$`" != "" ]; then
 echo "Trailing : in PATH"
fi
p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
 if [ "$1" = "." ]; then
 echo "PATH contains ."
 shift
 continue
 fi
 if [ -d $1 ]; then
 dirperm=`ls -ldH $1 | cut -f1 -d" "`
 if [ `echo $dirperm | cut -c6 ` != "-" ]; then
 echo "Group Write permission set on directory $1"
 fi
 if [ `echo $dirperm | cut -c9 ` != "-" ]; then
 echo "Other Write permission set on directory $1"
 fi
 dirown=`ls -ldH $1 | awk '{print $3}'`
 if [ "$dirown" != "root" ] ; then
 echo $1 is not owned by root
 fi
 else
 echo $1 is not a directory
 fi
 shift
done
"""
home_dir_exist = """#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 fi
done"""

home_dir_perm = """#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 dirperm=`ls -ld $dir | cut -f1 -d" "`
 if [ `echo $dirperm | cut -c6` != "-" ]; then
 echo "Group Write permission set on the home directory ($dir) of user
$user"
 fi
 if [ `echo $dirperm | cut -c8` != "-" ]; then
 echo "Other Read permission set on the home directory ($dir) of user
$user"
 fi
 if [ `echo $dirperm | cut -c9` != "-" ]; then
 echo "Other Write permission set on the home directory ($dir) of user
$user"
 fi
 if [ `echo $dirperm | cut -c10` != "-" ]; then
 echo "Other Execute permission set on the home directory ($dir) of user
$user"
 fi
 fi
done"""

home_dir_owner = """#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 owner=$(stat -L -c "%U" "$dir")
 if [ "$owner" != "$user" ]; then
 echo "The home directory ($dir) of user $user is owned by $owner."
 fi
fi
done"""
dot_files_writable = """#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 for file in $dir/.[A-Za-z0-9]*; do
 if [ ! -h "$file" -a -f "$file" ]; then
 fileperm=`ls -ld $file | cut -f1 -d" "`
 if [ `echo $fileperm | cut -c6` != "-" ]; then
 echo "Group Write permission set on file $file"
 fi
 if [ `echo $fileperm | cut -c9` != "-" ]; then
 echo "Other Write permission set on file $file"
 fi
 fi
 done
 fi
done"""
users_have_fwdfiles = """#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
 echo ".forward file $dir/.forward exists"
 fi
 fi
done"""

users_have_netrcfiles = """#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
 echo ".netrc file $dir/.netrc exists"
 fi
 fi
done"""

users_netrcfiles_writable = """#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 for file in $dir/.netrc; do
 if [ ! -h "$file" -a -f "$file" ]; then
 fileperm=`ls -ld $file | cut -f1 -d" "`
 if [ `echo $fileperm | cut -c5` != "-" ]; then
 echo "Group Read set on $file"
 fi
 if [ `echo $fileperm | cut -c6` != "-" ]; then
 echo "Group Write set on $file"
 fi
 if [ `echo $fileperm | cut -c7` != "-" ]; then
 echo "Group Execute set on $file"
 fi
 if [ `echo $fileperm | cut -c8` != "-" ]; then
 echo "Other Read set on $file"
 fi
 if [ `echo $fileperm | cut -c9` != "-" ]; then
 echo "Other Write set on $file"
 fi
 if [ `echo $fileperm | cut -c10` != "-" ]; then
 echo "Other Execute set on $file"
 fi
 fi
 done
 fi
done"""

users_rhosts_files = """#!/bin/bash
cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 for file in $dir/.rhosts; do
 if [ ! -h "$file" -a -f "$file" ]; then
 echo ".rhosts file in $dir"
 fi
 done
 fi
done"""

files_exist = """#!/bin/bash
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
 grep -q -P "^.*?:[^:]*:$i:" /etc/group
 if [ $? -ne 0 ]; then
 echo "Group $i is referenced by /etc/passwd but does not exist in
/etc/group"
 fi
done"""

duplicate_uids = """#!/bin/bash
cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
 echo "Duplicate UID ($2): ${users}"
 fi
done"""

duplicate_gids = """#!/bin/bash
cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
 echo "Duplicate GID ($2): ${groups}"
 fi
done"""

duplicate_users = """#!/bin/bash
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
 echo "Duplicate User Name ($2): ${uids}"
 fi
done"""
duplicate_groups = """#!/bin/bash
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
 echo "Duplicate Group Name ($2): ${gids}"
 fi
done"""

def ask_user():
    options_dict = {1: 'ubuntu', 2: 'centos', 3: 'Redhat/Oel'}
    count = 0
    while True:
        option = input("What is the operation system on the host?\n1. Ubuntu\n2. CentOS\n3. Redhat/Oel\nEnter 1/2/3")
        if count < 2 or option.isdigit():
            if int(option) not in [1, 2, 3]:
                print(f"Invalid option, you have {2-count} chances")
                count += 1
                continue
            else:
                operating_system = options_dict[int(option)]
                break
        else:
            print("Sorry, please re-run the code and choose a valid option")
            exit(1)
    return operating_system

def cmd_split(cmd):
    return shlex.split(cmd)

def run_command(cmd, grep = []):
    out, retcode = "", ""
    try:
        cmd_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if grep:
            for item in grep:
                grep_proc = subprocess.Popen(item, stdin=cmd_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = grep_proc.communicate()[0].decode()
            retcode = grep_proc.returncode
        else:
            out = cmd_proc.communicate()[0].decode()
            retcode = cmd_proc.returncode
    except Exception as e:
        print(f"Command execution failed with an exception {e} {cmd}")
    return out, retcode

class Benchmark():
    def __init__(self, operating_system):
        self.operating_sys = operating_system
        self.parentDict = {}

    def __check_package(self, pkg_name):
        myDict = {}
        if 'ubuntu' in self.operating_sys.lower():
            myDict['output'], retcode = run_command(cmd_split("dpkg -s {}".format(pkg_name)))
        else:
            myDict['output'], retcode = run_command(cmd_split(f"rpm -q {pkg_name}"))
        if retcode != 0:
            myDict['status'] = f"{pkg_name} is not Installed"
        else:
            myDict['status'] = f"{pkg_name} is Installed"
        return myDict

    def __is_enabled(self, service):
        return run_command(cmd_split(f'systemctl is-enabled {service}'))[0]


    def __check_file_permissions(self, file):
        if os.path.exists(file):
            stat = run_command(cmd_split(f"stat {file}"), [cmd_split("grep -i Access")])[0]
        else:
            stat = "File doesn't exist"
        return stat


        if os.path.exists(file):
            stat_output, _ = run_command(cmd_split(f"stat {file}"), [cmd_split("grep -i Access")])
            lines = stat_output.splitlines()
            access_line = lines[0] if lines else ""

            # Verify Uid and Gid
            if expected_uid_gid in access_line:
                # Verify permissions
                if file in expected_permissions and access_line.endswith(expected_permissions[file]):
                    return "Passed"

            return "Failed"
        else:
            return "File doesn't exist"
                
    def __execute_bash_script(self, cmd):
        if os.path.isfile('script.sh'):
            os.remove('script.sh')
        with open('script.sh', 'w') as f:
            f.write(cmd)
        output = run_command(cmd_split("bash script.sh"))[0]
        try:
            os.remove('script.sh')
        except OSError as e:
            print(f"Removing file failed with following error: {e}")
        return output

    def __unused_module(self, module):
        in_use = run_command("lsmod", [cmd_split(f"grep {module}")])[0]
        disabled = run_command(cmd_split(f'modprobe -n -v {module}'))[0]
        return {'lsmod': in_use, 'modprobe': disabled}

    def __sysctl_check(self, sysctl_cmd):
        myDict = {}
        if 'centos' in self.operating_sys.lower():
            sysctl_files.extend(glob.glob('/usr/lib/sysctl.d/*.conf'))
        if isinstance(sysctl_cmd, list):
            for item in sysctl_cmd:
                myDict['sysctl'] = run_command(cmd_split(f'sysctl {item}'))[0]
                for file in sysctl_files:
                    myDict[file] = run_command(cmd_split(f"grep -s {item} {file}"))[0]

        else:
            myDict[f'sysctl'] = run_command(cmd_split(f'sysctl {sysctl_cmd}'))[0]
            for file in sysctl_files:
                myDict[file] = run_command(cmd_split(f"grep -s {sysctl_cmd} {file}"))[0]
        return myDict

    def os_checks(self):
        if 'ubuntu' in self.operating_sys.lower():
            core_dump_term = "grep 'hard core'"
            adrs_space_key = "Ensure address space layout randomization (ASLR) is enabled"
            gdm_path = 'gdm3'
            ip_forward = "net.ipv4.ip_forward"
            for filesystem in ['cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus', 'udf']:
                self.parentDict[f"Ensure mounting of {filesystem} filesystems is disabled"] = self.__unused_module(filesystem)
            self.parentDict["Ensure separate partition exists for /tmp"] = \
                run_command("mount", [cmd_split(f'grep /tmp')])[0]
            self.parentDict["Ensure nodev option set on /tmp partition"] = \
                self.parentDict[f"Ensure separate partition exists for /tmp"]
            self.parentDict["Ensure nosuid option set on /tmp partition"] = \
                self.parentDict[f"Ensure separate partition exists for /tmp"]
            self.parentDict["Ensure package manager repositories are configured"] = \
                run_command(cmd_split("apt-cache policy"))[0]
            self.parentDict["Ensure GPG keys are configured"] = run_command(cmd_split('apt-key list'))[0]
            self.parentDict["Ensure filesystem integrity is regularly checked"] = {}
            self.parentDict["Ensure filesystem integrity is regularly checked"]['Crontab'] = \
                run_command(cmd_split("crontab -u root -l"), [cmd_split("grep aide")])[0]
            for file in cron_files:
                self.parentDict["Ensure filesystem integrity is regularly checked"][file] = \
                    run_command(cmd_split(f"grep -r aide {file}"))[0]
            self.parentDict['Ensure permissions on bootloader config are configured'] = \
                self.__check_file_permissions('/boot/grub/grub.cfg')

            self.parentDict['Ensure bootloader password is set'] = [
                run_command(cmd_split("grep '^set superusers' /boot/grub/grub.cfg"))[0],
                run_command(cmd_split("grep ^password /boot/grub/grub.cfg"))[0]]

            self.parentDict['Ensure authentication required for single user mode'] = \
                run_command(cmd_split("sudo cat /etc/shadow"), [cmd_split("grep ^root:[*\!]:")])[0]
            self.parentDict["Ensure XD/NX support is enabled"] = run_command("dmesg", [cmd_split('grep NX')])
            self.parentDict["Ensure prelink is disabled"] = self.__check_package('prelink')
            self.parentDict["Ensure SELinux is not disabled in bootloader configuration"] = \
                run_command(cmd_split('grep "^\s*linux" /boot/grub/grub.cfg'))[0]
            if os.path.exists('/etc/selinux/config'):
                selinux_enforcing = [run_command(cmd_split("grep SELINUX=enforcing /etc/selinux/config"))[0],
                                     run_command("sestatus")]
                selinux_configured = [run_command((cmd_split("grep SELINUXTYPE= /etc/selinux/config")))[0],
                                      run_command("sestatus")[0]]
            else:
                selinux_enforcing = "No such file or directory"
                selinux_configured = "No such file or directory"
            self.parentDict["Ensure the SELinux state is enforcing"] = selinux_enforcing
            self.parentDict["Ensure SELinux policy is configured"] = selinux_configured
            unconfined_daemons = """ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }'"""
            self.parentDict["Ensure no unconfined daemons exist"] = self.__execute_bash_script(unconfined_daemons)
            self.parentDict["Ensure AppArmor is not disabled in bootloader configuration"] = \
                self.parentDict["Ensure SELinux is not disabled in bootloader configuration"]
            self.parentDict["Ensure AppArmor is not disabled in bootloader configuration"] = \
                self.parentDict["Ensure SELinux is not disabled in bootloader configuration"]

            #self.parentDict["Ensure all AppArmor Profiles are enforcing"] = run_command(cmd_split("apparmor status"))[0]

            self.parentDict["Ensure SELinux or AppArmor are installed"] = {}
            self.parentDict["Ensure SELinux or AppArmor are installed"]["SELinux"] = self.__check_package('selinux')
            self.parentDict["Ensure SELinux or AppArmor are installed"]["AppArmor"] = self.__check_package('apparmor')
            self.parentDict["Ensure updates, patches, and additional security software are installed"] = \
                run_command(cmd_split("apt-get -s upgrade"))[0]
            for key, val in inetd_dict.items():
                if isinstance(val, list):
                    for service in val:
                        self.parentDict[f"Ensure {key} not enabled"] = {service: {}}
                        for file in inetd_files:
                            self.parentDict[f"Ensure {key} not enabled"][service][file] = run_command(cmd_split(f'grep "^{service}" {file}'))[0]
                else:
                    self.parentDict[f"Ensure {key} not enabled"] = {val:
                                                                        {file:
                                                                             run_command(cmd_split(f'grep "^{val}" {file}'))[0]}}
            self.parentDict["Ensure xinetd is not enabled"] = self.__check_package("xinetd")
            self.parentDict["Ensure openbsd-inetd is not installed"] = self.__check_package('openbsd-inetd')

            self.parentDict["Ensure time synchronization is in use"] = {'ntp': self.__check_package('ntp'),
                                                                         'chrony': self.__check_package('chrony')}
            myDict = {}
            if os.path.exists('/etc/ntp.conf'):
                myDict['Synchronization'] = run_command(cmd_split('grep "^restrict" /etc/ntp.conf'))[0]
                myDict['ntp_server'] = run_command(cmd_split('grep "^(server|pool)" /etc/ntp.conf'))[0]
                if os.path.exists('/etc/init.d/ntp'):
                    myDict['ntp_user'] = run_command(cmd_split('grep "RUNASUSER=ntp" /etc/init.d/ntp'))[0]
                else:
                    myDict['ntp_user'] = "No such file or directory /etc/init.d/ntp"
            else:
                myDict['Synchronization'] = "file /etc/ntp.conf doesn't exist"
                myDict['ntp_server'] = "file /etc/ntp.conf doesn't exist"
            self.parentDict['Ensure ntp is configured'] = myDict
            if os.path.exists('/etc/chrony/chrony.conf'):
                self.parentDict['Ensure chrony is configured'] = \
                run_command(cmd_split('grep "^(server|pool)" /etc/chrony/chrony.conf'))[0]
            else:
                self.parentDict["Ensure chrony is configured"] = "File /etc/chrony/chrony.conf doesn't exist"
            self.parentDict["Ensure X Window System is not installed"] = \
                run_command(cmd_split("dpkg -l xserver-xorg*"))[0]
            is_enabled_dict = {'Avahi Server is': 'avahi-daemon',
                               'CUPS is': 'cups', 'DHCP Server is': ['isc-dhcp-server', 'isc-dhcp-server6'],
                               'LDAP server is': 'slapd', 'NFS and RPC are': ['nfs-server', 'rpcbind'],
                               'DNS Server is': 'bind9', 'FTP Server is': 'vsftpd', 'HTTP server is': 'apache2',
                               'IMAP and POP3 server is': 'dovecot', 'Samba is': 'smbd', 'HTTP Proxy Server is': 'squid',
                               'SNMP Server is': 'snmpd', 'rsync service is': 'rsync', 'NIS Server is': 'nis'}
            for key, val in is_enabled_dict.items():
                if isinstance(val, list):
                    self.parentDict[f"Ensure {key} not enabled"] = {}
                    for item in val:
                        self.parentDict[f"Ensure {key} not enabled"][item] = \
                            run_command(cmd_split(f"systemctl is-enabled {item}"))[0]
                else:
                    self.parentDict[f"Ensure {key} not enabled"] = \
                        run_command(cmd_split(f"systemctl is-enabled {val}"))[0]
            self.parentDict["Ensure mail transfer agent is configured for local-only mode"] =\
                run_command(cmd_split('netstat -an'),
                            [cmd_split("grep LIST"), cmd_split("grep :22[[:space:]]")])[0]

            service_client_pkgs = {'NIS Client': 'nis', 'rsh client': ['rsh-client', 'rsh-redone-client'],
                                   'talk client': 'talk', 'telnet client': 'telnet', 'LDAP client': 'ldap-utils'}

            for key, val in service_client_pkgs.items():
                if isinstance(val, list):
                    for item in val:
                        self.parentDict[f"Ensure {key} is not installed"] = \
                            {item: self.__check_package(item)}
                else:
                    self.parentDict[f"Ensure {key} is not installed"] = self.__check_package(val)

            self.parentDict["Ensure IPv6 redirects are not accepted"] = \
                self.__sysctl_check(["net.ipv6.conf.all.accept_redirects",
                                               "net.ipv6.conf.all.accept_redirects"])
            self.parentDict["Ensure IPv6 is disabled"] = \
                self.parentDict["Ensure SELinux is not disabled in bootloader configuration"]

            self.parentDict["Ensure TCP Wrappers is installed"] = self.__check_package('tcpd')
            for file in ['hosts.allow', 'hosts.deny']:
                self.parentDict[f'Ensure permissions on /etc/{file} are configured'] = \
                    self.__check_file_permissions(f'/etc/{file}')
                with open(f'/etc/{file}', 'r') as f:
                    self.parentDict[f"Ensure /etc/{file} is configured"] = f.readlines()

            self.parentDict["Ensure iptables is installed"] = self.__check_package('iptables')
            # Super user access
            self.parentDict["Ensure default deny firewall policy"] = run_command(cmd_split("sudo iptables -L"))[0]
            self.parentDict["Ensure loopback traffic is configured"] = \
                {"loopback_input": run_command(cmd_split("sudo iptables -L INPUT -v -n"))[0],
                 "loopback_output": run_command(cmd_split("sudo iptables -L OUTPUT -v -n"))[0]}
            out_estb_conn = "Ensure outbound and established connections are configured"
            self.parentDict['Ensure firewall rules exist for all open ports'] = \
                {'open ports':run_command(cmd_split("netstat -ln"))[0],
                 "Firewall rules": run_command((cmd_split("sudo iptables -L INPUT -v -n")))[0]}

            # 3.7 Ensure wireless interfaces are disabled
            if self.__check_package('wireless-tools') == "Installed":
                self.parentDict["Ensure wireless interfaces are disabled"] = run_command("iwconfig")[0]
            else:
                self.parentDict["Ensure wireless interfaces are disabled"] = "Command iwconfig not found"
            self.parentDict["Ensure auditing for processes that start prior to auditd is enabled"] = \
                self.parentDict["Ensure SELinux is not disabled in bootloader configuration"]

            for key, val in audit_dict.items():
                if os.path.exists('/etc/audit/audit.rules'):
                    self.parentDict[f'Ensure {key}'] = \
                        {'audit.rules':run_command(cmd_split("grep {val} /etc/audit/audit.rules"))[0],
                         'auditctl': run_command(cmd_split("auditctl -l"), [cmd_split("grep {val}")])[0]}
                else:
                    self.parentDict[f'Ensure {key}'] = "Path /etc/audit/audit.rules doesn't exist"
            priv_cmd_scpt = """find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"}'find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"}'"""
            self.parentDict["Ensure use of privileged commands is collected"] = self.__execute_bash_script(priv_cmd_scpt)
            self.parentDict["Ensure the audit configuration is immutable"] = \
                run_command(cmd_split('sudo cat /etc/audit/audit.rules'), [cmd_split("grep ^\s*[^#]"), cmd_split("tail -1")])[0]
            self.parentDict["Ensure syslog-ng service is enabled"] = self.__is_enabled('syslog-ng')
            # 4.2.2.3
            if os.path.exists('/etc/syslog-ng/syslog-ng.conf'):
                self.parentDict["Ensure syslog-ng default file permissions configured"] = \
                    run_command(cmd_split("grep ^options /etc/syslog-ng/syslog-ng.conf"))[0]
                self.parentDict["Ensure syslog-ng is configured to send logs to a remote log host"] = \
                    run_command(cmd_split("cat /etc/syslog-ng/syslg-ng.conf"))[0]
                self.parentDict["Ensure remote syslog-ng messages are only accepted on designated log hosts"] = \
                    self.parentDict["Ensure syslog-ng is configured to send logs to a remote log host"]
            else:
                out = "file /etc/syslog-ng/syslog-ng.conf doesn't exist"
                self.parentDict["Ensure syslog-ng default file permissions configured"] = out
                self.parentDict["Ensure syslog-ng is configured to send logs to a remote log host"] = out
                self.parentDict["Ensure remote syslog-ng messages are only accepted on designated log hosts"] = out

            # 4.2.3
            self.parentDict["Ensure rsyslog or syslog-ng is installed"] = \
                {'rsyslog': self.__check_package('rsyslog'),
                 'syslog-ng': self.__check_package('syslog-ng')}

            self.parentDict["Ensure permissions on all logfiles are configured"] = \
                run_command(cmd_split("sudo find /var/log -type f -ls"))[0]
            for key, val in ssh_dict.items():
                if 'PAM' in key or 'AllowTcp' in key or 'MaxStartups' in key or 'MaxSessions' in key:
                    continue
                if not isinstance(val, list):
                    self.parentDict[f"Ensure {key}"] = run_command(cmd_split(f"grep {val} /etc/ssh/sshd_config"))[0]
                else:
                    self.parentDict[f"Ensure {key}"] = {}
                    for value in val:
                        self.parentDict[f"Ensure {key}"][value[1:]] = run_command(cmd_split(f"grep {value} /etc/ssh/sshd_config"))[0]

            if os.path.exists('/etc/pam.d/common-password'):
                self.parentDict["Ensure password creation requirements are configured"] = \
                    {'Strength of password':
                         run_command(cmd_split("grep pam_pwquality.so /etc/pam.d/common-password"))[0]}
            else:
                self.parentDict["Ensure password creation requirements are configured"] = \
                    {'Strength of password': "file /etc/pam.d/common-password doesn't exist"}
            if os.path.exists('/etc/security/pwquality.conf'):
                for policy in ['minlen', 'dcredit', 'ucredit', 'ocredit', 'lcredit']:
                    self.parentDict["Ensure password creation requirements are configured"] = \
                        {f"policy_{policy}": run_command(cmd_split(f"grep {policy} /etc/security/pwquality.conf"))[0]}
            else:
                self.parentDict["Ensure password creation requirements are configured"] = \
                    "file /etc/security/pwquality.conf doesn't exist"

            # 5.3.2
            if os.path.exists('/etc/pam.d/common-auth'):
                self.parentDict["Ensure lockout for failed password attempts is configured"] = \
                    run_command(cmd_split("grep pam_tally2 /etc/pam.d/common-auth"))[0]
            else:
                self.parentDict["Ensure lockout for failed password attempts is configured"] = \
                    "file /etc/pam.d/common-auth doesn't exist"

            # 5.3.3 - 5.3.4
            if os.path.exists('/etc/pam.d/common-password'):
                self.parentDict["Ensure password reuse is limited"] = \
                    run_command(cmd_split("egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/common-password"))[0]
                self.parentDict["Ensure password hashing algorithm is SHA-512"] = \
                    run_command(cmd_split("egrep '^password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512' /etc/pam.d/common-password"))[0]
            else:
                self.parentDict["Ensure password reuse is limited"] = \
                    "file /etc/pam.d/common-password doesn't exist"
                self.parentDict["Ensure password hashing algorithm is SHA-512"] = \
                    "file /etc/pam.d/common-password doesn't exist"


            # 5.4.1.5
            self.parentDict["Ensure all users last password change date is in the past"] = \
                run_command(cmd_split("sudo cat /etc/shadow"), [cmd_split("cut -d: -f1")])[0]

            # 5.4.2
            sys_acc = """egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}'
            for user in `awk -F: '($1!="root" && $3 < 1000) {print $1 }' /etc/passwd`; do passwd -S $user | awk -F ' ' '($2!="L") {print $1}'; done"""
            self.parentDict["Ensure system accounts are non-login"] = self.__execute_bash_script(sys_acc)

            files = ['/etc/bash.bashrc', '/etc/profile'] + glob.glob('/etc/profile.d/*.sh')
            self.parentDict["Ensure default user umask is 027 or more restrictive"] = {}
            self.parentDict["Ensure default user shell timeout is 900 seconds or less"]= {}

            for file in files:
                self.parentDict["Ensure default user umask is 027 or more restrictive"][file] = \
                    {file: run_command(cmd_split(f"grep umask {file}"))[0]}
                self.parentDict["Ensure default user shell timeout is 900 seconds or less"][file] = \
                    {file: run_command(cmd_split(f"grep ^TMOUT {file}"))[0]}

            self.parentDict["Audit system file permissions"] = {
                "pkg": run_command(cmd_split("dpkg -S /bin/bash"))[0],
                "verify": run_command(cmd_split("dpkg --verify bash"))[0]}

# CENTOS CHECKS
        else:
            core_dump_term = "grep -E '^\s*\*\s+hard\s+core'"
            adrs_space_key = "Ensure address space layout randomization (ASLR) is enabled"
            gdm_path = 'gdm'
            ip_forward = ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"]
            out_estb_conn = "Ensure iptables outbound and established connections are configured"
            for filesystem in ['cramfs', 'svfat', 'squashfs', 'udf']:
                if 'vfat' in filesystem:
                    self.parentDict[f"Ensure mounting of vFAT filesystems is limited"] = self.__unused_module(filesystem)
                else:
                    self.parentDict[f"Ensure mounting of {filesystem} filesystems is disabled"] = self.__unused_module(filesystem)
            self.parentDict["Ensure /tmp is configured"] = run_command("mount", [cmd_split(f'grep /tmp')])[0]
            self.parentDict["Ensure nodev option set on /tmp partition"] = \
                self.parentDict["Ensure /tmp is configured"]
            self.parentDict["Ensure nosuid option set on /tmp partition"] = \
                self.parentDict["Ensure /tmp is configured"]
            self.parentDict["Ensure noexec option set on /tmp partition"] = \
                self.parentDict["Ensure /tmp is configured"]
            self.parentDict["Ensure GPG keys are configured"] = \
                run_command(cmd_split("rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'"))[0]
            self.parentDict["Ensure package manager repositories are configured"] = \
                run_command(cmd_split("dnf repolist"))[0]
            self.parentDict["Ensure gpgcheck is globally activated"] = \
                run_command(cmd_split("grep ^gpgcheck /etc/yum.conf"))[0]
            self.parentDict["Ensure sudo is installed"] = run_command(cmd_split("rpm -q sudo"))[0]
            self.parentDict["Ensure sudo commands use pty"] = \
            run_command(cmd_split("sudo cat /etc/sudoers"), [cmd_split("grep -Ei '^\s*Defaults\s+(\[^#]+,\s*)?use_pty'")])[0]
            self.parentDict["Ensure sudo log file exists"] = {}
            for file in sudoer_files:
                self.parentDict["Ensure sudo log file exists"][file] = \
                    run_command(cmd_split(f"grep -Esi '^\s*Defaults\s+([^#]+,\s*)?logfile=' {file}"))[0]
            self.parentDict["Ensure filesystem integrity is regularly checked"] = {}
            for service in ['aidecheck.service', 'aide-check.timer']:
                self.parentDict["Ensure filesystem integrity is regularly checked"][service] = {}
                self.parentDict["Ensure filesystem integrity is regularly checked"][service]["is_enabled"] = \
                    self.__is_enabled(service)
                self.parentDict["Ensure filesystem integrity is regularly checked"][service]["status"] = \
                    run_command(cmd_split(f"systemctl status {service}"))[0]
            self.parentDict["Ensure permissions on bootloader config are configured"] = \
                self.__execute_bash_script(bootloader_permissions)
            self.parentDict["Ensure bootloader password is set"] = self.__execute_bash_script(bootloader_passwd)
            self.parentDict["Ensure authentication required for single user mode"] = {}
            self.parentDict["Ensure authentication required for single user mode"]['rescue_service'] = \
                run_command(cmd_split("grep  /systemd-sulogin-shell /usr/lib/systemd/system/rescue.service"))[0]
            self.parentDict["Ensure authentication required for single user mode"]["emergency_service"] = \
                run_command(cmd_split("grep /systemd-sulogin-shell /usr/lib/systemd/system/emergency.service"))[0]
            self.parentDict["Ensure SELinux is installed"] = self.__check_package('libselinux')
            self.parentDict["Ensure SELinux is not disabled in bootloader configuration"] = \
                run_command(cmd_split('grep -E "kernelopts=(\S+\s+)*(selinux=0|enforcing=0)+\b" /boot/grub2/grubenv'))[0]
            if os.path.exists('/etc/selinux/config'):
                selinux_configured = {"targeted/mls":
                                          run_command(cmd_split('grep -E "^\s*SELINUXTYPE=(targeted|mls)\b" /etc/selinux/config'))[0],
                                      'sestatus':
                                          run_command("sestatus", [cmd_split("grep Loaded")])[0]}
                selinux_enforcing = {'/etc/selinux/config':
                                         run_command(cmd_split("grep -E '^\s*SELINUX=enforcing' /etc/selinux/config"))[0],
                                     'sestatus': run_command("sestatus")[0]}
            else:
                selinux_enforcing = "No such file or directory /etc/selinux/config"
                selinux_configured = "No such file or directory /etc/selinux/config"
            self.parentDict["Ensure SELinux policy is configured"] = selinux_configured
            self.parentDict["Ensure the SELinux state is enforcing"] = selinux_enforcing

            self.parentDict["Ensure no unconfined services exist"] = \
            run_command(cmd_split("ps -ez"), [cmd_split("grep unconfined_service_t")])[0]
            self.parentDict["Ensure SETroubleshoot is not installed"] = self.__check_package('setroubleshoot')
            self.parentDict["Ensure the MCS Translation Service (mcstrans) is not installed"] = \
                self.__check_package('mcstrans')
            self.parentDict["Ensure updates, patches, and additional security software are installed"] = \
                run_command(cmd_split("dnf check-update"))[0]
            if os.path.exists(' /etc/crypto-policies/config'):
                self.parentDict["Ensure system-wide crypto policy is not legacy"] = \
                    run_command(cmd_split(" grep -E -i '^\s*LEGACY\s*(\s+#.*)?$' /etc/crypto-policies/config"))[0]
                self.parentDict["Ensure system-wide crypto policy is FUTURE or FIPS"] = \
                    run_command(cmd_split("grep -E -i '^\s*(FUTURE|FIPS)\s*(\s+#.*)?$' /etc/crypto-policies/config"))[0]
            else:
                self.parentDict[
                    "Ensure system-wide crypto policy is not legacy"] = \
                    "File doesn't exist /etc/crypto-policies/config"
                self.parentDict["Ensure system-wide crypto policy is FUTURE or FIPS"] = \
                    "File doesn't exist /etc/crypto-policies/config"
            self.parentDict["Ensure xinetd is not installed"] = self.__check_package('xinetd')
            self.parentDict["Ensure time synchronization is in use"] = self.__check_package('chrony')
            if os.path.exists("/etc/chrony.conf"):
                self.parentDict["Ensure chrony is configured"] = {}
                self.parentDict["Ensure chrony is configured"]['server|pool'] = \
                    run_command(cmd_split("grep -E '^(server|pool)' /etc/chrony.conf"))[0]
                self.parentDict["Ensure chrony is configured"]['proces'] = \
                    run_command(cmd_split('ps -ef'), [cmd_split('grep chronyd')])[0]
            else:
                self.parentDict["Ensure chrony is configured"] = "/etc/chrony.conf file doesn't exist"
            self.parentDict["Ensure X Window System is not installed"] = self.__check_package("xorg-x11-server-*")
            service_dict = {'rsync service': 'rsyncd', 'Avahi Server': 'avahi-daemon.socket', 'SNMP Server': 'snmpd',
                            'HTTP Proxy Server': 'squid', 'Samba': 'smb', 'IMAP and POP3 server': 'dovecot',
                            'HTTP server': 'httpd', 'FTP Server': 'vsftpd', 'DNS Server': 'named', 'NFS': 'nfs-server',
                            'RPC': 'rpcbind', 'LDAP server': 'slapd', 'DHCP Server': 'dhcpd', 'CUPS': 'cups',
                            'NIS Server': 'ypserv'}
            for key, val in service_dict.items():
                self.parentDict[f"Ensure {key} is not enabled"] = self.__is_enabled(val)
            self.parentDict["Ensure mail transfer agent is configured for local-only mode"] = \
                run_command(cmd_split("ss -lntu"), [cmd_split("grep -E ':25\s'"),
                                                    cmd_split("grep -E -v '\s(127.0.0.1|::1):25\s'")])[0]

            service_client_dict = {'NIS Client': 'ypbind', 'telnet client': 'telnet',
                                   'LDAP client': 'openldap-clients'}
            for key, value in service_client_dict.items():
                self.parentDict[f"Ensure {key} is not installed"] = self.__check_package(val)
            self.parentDict["Ensure a Firewall package is installed"] = self.__check_package('firewalld')
            self.parentDict["Ensure firewalld service is enabled and running"] = self.__is_enabled('firewalld')
            self.parentDict["Ensure iptables service is not enabled with firewalld"] = \
                run_command(cmd_split("systemctl status iptables"))[0]
            self.parentDict["Ensure nftables is not enabled with firewalld"] = self.__is_enabled('nftables')
            self.parentDict["Ensure firewalld default zone is set"] = \
                run_command(cmd_split("firewall-cmd --get-default-zone"))[0]
            nw_iface_zone = """nmcli -t connection show | awk -F: '{if($4){print $4}}' | while read INT;do firewall-cmd --get-active-zones | grep -B1 $INT; done"""
            drop_svcs_ports = """firewall-cmd --get-active-zones | awk '!/:/ {print $1}' | while read ZN; do firewall-cmd --list-all --zone=$ZN; done"""
            self.parentDict["Ensure network interfaces are assigned to appropriate zone"] = \
                self.__execute_bash_script(nw_iface_zone)
            self.parentDict["Ensure firewalld drops unnecessary services and ports"] = \
                self.__execute_bash_script(drop_svcs_ports)
            self.parentDict["Ensure iptables are flushed with nftables"] = \
                {'ipv4': run_command(cmd_split("sudo iptables -L"))[0],
                 'ipv6': run_command(cmd_split("sudo ip6tables -L"))[0]}
            self.parentDict["Ensure an nftables table exists"] = run_command(cmd_split("nft list tables"))
            self.parentDict["Ensure nftables base chains exist"] = \
                {'hook input': run_command(cmd_split('nft list ruleset'), [cmd_split("grep 'hook input'")])[0],
                 'hook forward': run_command(cmd_split('nft list ruleset'), [cmd_split("grep 'hook forward'")])[0],
                 'hook output': run_command(cmd_split('nft list ruleset'), [cmd_split("grep 'hook output'")])[0]}
            self.parentDict["Ensure nftables loopback traffic is configured"] = \
                {'accept':
                     self.__execute_bash_script("""nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept'"""),
                 'saddr':
                     self.__execute_bash_script("""nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'"""),
                 'ip6 saddr':
                     self.__execute_bash_script(""" nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'""")}
            self.parentDict["Ensure nftables outbound and established connections are configured"] = \
                {"hook input":
                     self.__execute_bash_script(
                         """nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'"""),
                 "hook ouput":
                    self.__execute_bash_script(
                        """nft list ruleset | awk '/hook ouput/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'"""
                    )}
            self.parentDict["Ensure nftables default deny firewall policy"] = \
                self.parentDict["Ensure nftables base chains exist"]
            self.parentDict["Ensure nftables service is enabled"] =\
                self.parentDict["Ensure nftables is not enabled with firewalld"]

            self.parentDict["Ensure nftables rules are permanent"] = {}
            for pattern in ['hook input', 'hook forward', 'hook output']:
                if os.path.exists('/etc/sysconfig/nftables.conf'):
                    nft_prmt = """[[ -n $(grep -E "^\s*include" /etc/sysconfig/nftables.conf) ]] && awk '/%s/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf)""" %(pattern)
                    self.parentDict["Ensure nftables rules are permanent"] = self.__execute_bash_script(nft_prmt)
                else:
                    self.parentDict["Ensure nftables rules are permanent"] = "/etc/sysconfig/nftables.conf doesn't exist"
            self.parentDict["Ensure iptables default deny firewall policy"] = self.parentDict["Ensure iptables are flushed with nftables"]["ipv4"]
            self.parentDict["Ensure iptables firewall rules exist for all open ports"] = \
                {'ss': run_command(cmd_split("ss -4tuln"))[0],
                 'iptables': run_command(cmd_split("sudo iptables -L INPUT -v -n"))[0]}
            self.parentDict["Ensure iptables loopback traffic is configured"] = self.parentDict["Ensure iptables firewall rules exist for all open ports"]['iptables']
            self.parentDict["Ensure iptables is enabled and active"] = self.__is_enabled('iptables')
            self.parentDict["Ensure ip6tables default deny firewall policy"] = \
                run_command(cmd_split("sudo ip6tables -L"))[0]
            self.parentDict["Ensure ip6tables loopback traffic is configured"] = \
                run_command(cmd_split("sudo ip6tables -L INPUT -v -n"))[0]
            self.parentDict["Ensure ip6tables outbound and established connections are configured"] = \
                self.parentDict["Ensure ip6tables loopback traffic is configured"]
            self.parentDict["Ensure ip6tables firewall rules exist for all open ports"] =\
                {'ss': run_command(cmd_split("ss -6tuln"))[0],
                'iptables': self.parentDict["Ensure ip6tables loopback traffic is configured"]}
            self.parentDict["Ensure ip6tables is enabled and active"] = self.__is_enabled("ip6tables")
            self.parentDict["Ensure wireless interfaces are disabled"] = \
                run_command(cmd_split("nmcli radio all"))[0]
            self.parentDict["Disable IPv6"] = self.__execute_bash_script(ipv6_disable)
            self.parentDict["Ensure auditd is installed"] = self.__check_package('auditd')
            self.parentDict["Ensure auditing for processes that start prior to auditd is enabled"] = \
                run_command(cmd_split("sudo cat /boot/grub2/grubenv"), [cmd_split("grep -E 'kernelopts=(\S+\s+)*audit=1\b'")])[0]
            self.parentDict["Ensure audit_backlog_limit is sufficient"] =\
                run_command(cmd_split("sudo cat /boot/grub2/grubenv"), [cmd_split("grep -E 'kernelopts=(\S+\s+)*audit_backlog_limit=\S+\b'")])[0]

            audit_files = glob.glob('/etc/audit/rules.d/*.rules')
            for key, val in audit_dict.items():
                if audit_files:
                    for file in audit_files:
                        self.parentDict[f'Ensure {key}'] = \
                            {file: {'audit.rules': run_command(cmd_split("grep {val} {file}"))[0]}}
                    self.parentDict[f'Ensure {key}'] =\
                        {'auditctl': run_command(cmd_split("auditctl -l"), [cmd_split("grep {val}")])[0]}
                else:
                    self.parentDict[f'Ensure {key}'] =\
                        "Path /etc/audit/rules.d/*.conf doesn't exist"
            priv_comm = """find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }'"""
            self.parentDict["Ensure use of privileged commands is collected"] = self.__execute_bash_script(priv_comm)

            if audit_files:
                for file in audit_files:
                    self.parentDict["Ensure the audit configuration is immutable"] = \
                        {file: run_command(cmd_split('grep "^\s*[^#]" /etc/audit/audit.rules'), [cmd_split("tail -1")])[0]}
            else:
                self.parentDict["Ensure the audit configuration is immutable"] = "No files exist /etc/audit/rules.d/*.rules"
            print(self.parentDict.keys())
            self.parentDict["Ensure rsyslog is installed"] = self.__check_package("rsyslog")
            self.parentDict["Ensure SSH access is limited"] = \
                {'sshd': self.__execute_bash_script("""sudo sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$'"""),
                 'grep': run_command(cmd_split("sudo cat /etc/ssh/sshd_config"), [cmd_split("grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$'")])[0]}
            self.parentDict["Ensure permissions on SSH private host key files are configured"] = \
                run_command(cmd_split("find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;"))[0]
            self.parentDict["Ensure permissions on SSH public host key files are configured"] = \
                run_command(cmd_split("find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;"))[0]
            for key, val in ssh_dict.items():
                if 'Protocol' in key or 'MAC' in key or 'limited' in key:
                    continue
                if 'LogLevel' in key:
                    key = "SSH LogLevel is appropriate"
                if isinstance(val, list):
                    for v in val:
                        self.parentDict[f"Ensure {key}"] = \
                            {v: {'sshd': self.__execute_bash_script(
                                """sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep {v[1:].lower()}"""),
                             'grep': run_command(cmd_split("sudo cat /etc/ssh/sshd_config"),[cmd_split(f"grep -i '{v}'"), cmd_split("grep -Evi '(VERBOSE|INFO)'")])[0]}}
                else:
                    self.parentDict[f"Ensure {key}"] = \
                        {'sshd': self.__execute_bash_script("""sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep {val[1:].lower()}"""),
                        'grep': run_command(cmd_split("sudo cat /etc/ssh/sshd_config"),[cmd_split(f"grep -i '{val}'"), cmd_split("grep -Evi '(VERBOSE|INFO)'")])[0]}
            self.parentDict["Ensure system-wide crypto policy is not over-ridden"] = \
                run_command(cmd_split("cat /etc/sysconfig/sshd"), [cmd_split("grep -i '^\s*CRYPTO_POLICY='")])[0]
            self.parentDict["Create custom authselect profile"] = \
                run_command(cmd_split("authselect current"), [cmd_split('grep "Profile ID: custom"')])[0]
            self.parentDict["Select authselect profile"] = run_command(cmd_split("authselect current"))[0]
            for file in ["/etc/authselect/password-auth", "/etc/authselect/system-auth"]:
                self.parentDict["Ensure authselect includes with-faillock"] = {file: run_command(cmd_split(f"grep pam_faillock.so {file}"))}

            for file in ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]:
                self.parentDict["Ensure password creation requirements are configured"] =\
                    {file: run_command(cmd_split(f'grep pam_pwquality.so {file}'))[0]}
                self.parentDict["Ensure lockout for failed password attempts is configured"] = \
                    {file: run_command(cmd_split(f"grep -E '^\s*auth\s+required\s+pam_faillock.so\s+' {file}"))[0]}
                self.parentDict["Ensure password hashing algorithm is SHA-512"] = \
                    {file: run_command(cmd_split(f"grep -E '^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512\s*.*$' {file}"))[0]}
            self.parentDict["Ensure password creation requirements are configured"] = \
                {'minlen': run_command(cmd_split("grep ^minlen /etc/security/pwquality.conf"))[0],
                 'minclass': run_command(cmd_split("grep ^minclass /etc/security/pwquality.conf"))[0]}

            self.parentDict["Ensure password reuse is limited"] = run_command(cmd_split("grep -P '^\h*password\h+(requisite|sufficient)\h+(pam_pwhistory\.so|pam_unix\.so)\h+([^#\n\r]+\h+)?remember=([5-9]|[1-9][0-9]+)\h*(\h+.*)?$' /etc/pam.d/systemauth"))[0]
            sysacc_1 = """awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd"""
            sysacc_2 = """awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}'"""
            self.parentDict["Ensure system accounts are secured"] = {'script1': self.__execute_bash_script(sysacc_1),
                                                                     'script2': self.__execute_bash_script(sysacc_2)}

            self.parentDict["Ensure default user shell timeout is 900 seconds or less"] = self.__execute_bash_script(user_shell_tmout)
            passwd_change = """for usr in $(sudo cat /etc/shadow | cut -d: -f1); do [[ $(sudo chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr :$(chage -- list $usr | grep '^Last password change' | cut -d: -f2)"; done"""
            self.parentDict["Ensure all users last password change date is in the past"] = self.__execute_bash_script(passwd_change)

            out = run_command(cmd_split("rpm -qf /bin/bash"))[0]
            self.parentDict["Audit system file permissions"] = run_command(cmd_split(f"rpm -V {out}"))

#COMMON STUFF
        self.parentDict["Ensure separate partition exists for /var"] = \
            run_command("mount", [cmd_split('grep /var')])[0]
        self.parentDict["Ensure separate partition exists for /var/tmp"] = \
            run_command("mount", [cmd_split('grep /var')])[0]
        self.parentDict["Ensure nodev option set on /var/tmp partition"] = \
            self.parentDict["Ensure separate partition exists for /var/tmp"]
        self.parentDict["Ensure nosuid option set on /var/tmp partition"] = \
            self.parentDict["Ensure separate partition exists for /var/tmp"]
        self.parentDict["Ensure noexec option set on /var/tmp partition"] = \
            self.parentDict["Ensure separate partition exists for /var/tmp"]
        self.parentDict["Ensure separate partition exists for /var/log"] = \
            run_command("mount", [cmd_split('grep /var/log')])[0]
        self.parentDict["Ensure separate partition exists for /var/log/audit"] = \
            run_command("mount", [cmd_split('grep /var/log/audit')])[0]
        self.parentDict["Ensure separate partition exists for /home"] = \
            run_command("mount", [cmd_split(f'grep /home')])[0]
        self.parentDict["Ensure nodev option set on /home partition"] = self.parentDict[
            f"Ensure separate partition exists for /home"]
        self.parentDict["Ensure nodev option set on /dev/shm partition"] = \
            run_command("mount", [cmd_split("grep /dev/shm")])[0]
        self.parentDict["Ensure nosuid option set on /dev/shm partition"] = \
            self.parentDict["Ensure nodev option set on /dev/shm partition"]
        self.parentDict["Ensure noexec option set on /dev/shm partition"] = \
            self.parentDict["Ensure nodev option set on /dev/shm partition"]
        self.parentDict["Ensure nodev option set on removable media partitions"] = run_command("mount")[0]
        self.parentDict["Ensure nosuid option set on removable media partitions"] = self.parentDict["Ensure nodev option set on removable media partitions"]
        self.parentDict["Ensure noexec option set on removable media partitions"] = self.parentDict["Ensure nodev option set on removable media partitions"]
        # Check if sticky is set on all writable directories
        sticky_bit = """df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null"""
        self.parentDict["Ensure sticky bit is set on all world-writable directories"] = self.__execute_bash_script(
            sticky_bit)
        # Disable automounting
        self.parentDict['Disable Automounting'] = self.__is_enabled('autofs')
        # Disable usb_storage
        self.parentDict['Disable USB Storage'] = self.__unused_module('usb-storage')
        self.parentDict["Ensure AIDE is installed"] = self.__check_package("aide")

        myDict = {'check_security_limits_files': {}, 'check_syslog_files': {}}
        for file in security_limits_files:
            myDict['check_security_limits_files'][file] = run_command(cmd_split(f"{core_dump_term} {file}"))[0]
        for file in sysctl_files:
            myDict['check_syslog_files'][file] = run_command(cmd_split(f"grep 'fs\.suid_dumpable' {file}"))[0]

        myDict['suid_dumpable_sysctl'] = run_command(cmd_split("sysctl fs.suid_dumpable"))[0]
        self.parentDict["Ensure core dumps are restricted"] = myDict

        self.parentDict[adrs_space_key] = {}
        self.parentDict[adrs_space_key]['sysctl'] = \
        run_command(cmd_split("sysctl kernel.randomize_va_space"))[0]
        for file in sysctl_files:
            self.parentDict[adrs_space_key][file] = \
                run_command(cmd_split(f"grep 'kernel\.randomize-va_space' {file}"))[0]
        self.parentDict["Ensure message of the day is configured properly"] = \
            run_command(cmd_split("cat /etc/motd"))[0]
        self.parentDict["Ensure local login warning banner is configured properly"] = \
            run_command(cmd_split("cat /etc/issue"))[0]
        self.parentDict["Ensure remote login warning banner is configured properly"] = \
            run_command(cmd_split("cat /etc/issue.net"))[0]
        for file in ['/etc/motd', '/etc/issue', '/etc/issue.net']:
            self.parentDict[f"Ensure permissions on {file} are configured"] = self.__check_file_permissions(file)
        if os.path.exists(f'/etc/{gdm_path}/greeter.dconf-defaults'):
            self.parentDict['Ensure GDM login banner is configured'] = run_command(cmd_split(f"grep -A2 'org/gnome/login-screen' /etc/{gdm_path}/greeter.dconf-defaults"))[0]
        else:
            self.parentDict['Ensure GDM login banner is configured'] = f"File /etc/{gdm_path}/greeter.dconf-defaults doesn't exist"
        self.parentDict["Ensure IP forwarding is disabled"] = self.__sysctl_check(ip_forward)
        self.parentDict["Ensure packet redirect sending is disabled"] = \
            self.__sysctl_check(['net.ipv4.conf.all.send_redirects',
                          'net.ipv4.conf.default.send_redirects'])
        self.parentDict["Ensure source routed packets are not accepted"] = \
            self.__sysctl_check(['net.ipv4.conf.all.accept_source_route',
                                 ' net.ipv4.conf.default.accept_source_route'])
        self.parentDict["Ensure ICMP redirects are not accepted"] = \
            self.__sysctl_check(['net.ipv4.conf.all.accept_redirects',
                                 'net.ipv4.conf.default.accept_redirects'])
        self.parentDict["Ensure secure ICMP redirects are not accepted"] = \
            self.__sysctl_check(["net.ipv4.conf.all.secure_redirects",
                                 "net.ipv4.conf.default.secure_redirects"])
        self.parentDict["Ensure suspicious packets are logged"] = self.__sysctl_check(["net.ipv4.conf.all.log_martians",
                                                     "net.ipv4.conf.default.log_martians"])
        self.parentDict["Ensure broadcast ICMP requests are ignored"] = \
            self.__sysctl_check("net.ipv4.icmp_echo_ignore_broadcasts")
        self.parentDict["Ensure bogus ICMP responses are ignored"] = \
            self.__sysctl_check("net.ipv4.icmp_ignore_bogus_error_responses")
        self.parentDict["Ensure Reverse Path Filtering is enabled"] = \
            self.__sysctl_check(["net.ipv4.conf.all.rp_filter",
                                 "net.ipv4.conf.default.rp_filter"])
        self.parentDict["Ensure TCP SYN Cookies is enabled"] = self.__sysctl_check("net.ipv4.tcp_syncookies")
        self.parentDict["Ensure IPv6 router advertisements are not accepted"] = \
                self.__sysctl_check(["net.ipv6.conf.all.accept_ra",
                                     "net.ipv6.conf.default.accept_ra"])
        for protocol in ['dccp', 'sctp', 'rds', 'tipc']:
            self.parentDict[f"Ensure {protocol.upper()} is disabled"] = self.__unused_module(protocol)
        self.parentDict[out_estb_conn] = \
            run_command(cmd_split("sudo iptables -L -v -n"))[0]

        if os.path.exists('/etc/audit/auditd.conf'):
            # 4.1.1.1 Ensure audit log storage size is configured
            self.parentDict["Ensure audit log storage size is configured"] = \
                run_command(cmd_split("grep max_log_file /etc/audit/auditd.conf"))[0]

            # 4.1.1.2 Ensure system is disabled when audit logs are full
            myList = []
            for search in ['space_left_action', 'action_mail_acct', 'admin_space_left_action']:
                myList.append(run_command(cmd_split(f"grep {search} /etc/audit/auditd.conf"))[0])
            self.parentDict["Ensure system is disabled when audit logs are full"] = myList

            # 4.1.1.3 Ensure audit logs are not automatically deleted
            self.parentDict["Ensure audit logs are not automatically deleted"] = \
                run_command(cmd_split("grep max_log_file_action /etc/audit/auditd.conf"))[0]
        else:
            out = "file /etc/audit/auditd.conf doesn't exist"
            self.parentDict["Ensure audit log storage size is configured"] = out
            self.parentDict["Ensure system is disabled when audit logs are full"] = out
            self.parentDict["Ensure audit logs are not automatically deleted"] = out
        self.parentDict["Ensure auditd service is enabled"] = self.__is_enabled('auditd')
        self.parentDict["Ensure rsyslog Service is enabled"] = self.__is_enabled('rsyslog')
        self.parentDict["Ensure logging is configured"] = run_command(cmd_split("ls -l /var/log"))[0]
        self.parentDict["Ensure rsyslog default file permissions configured"] = {}
        self.parentDict["Ensure rsyslog is configured to send logs to a remote log host"] = {}
        self.parentDict["Ensure remote rsyslog messages are only accepted on designated log hosts."] = {}
        for file in rsyslog_files:
            self.parentDict["Ensure rsyslog default file permissions configured"][file] = \
                run_command(cmd_split(f"grep ^\$FileCreateMode {file}"))[0]
            self.parentDict["Ensure rsyslog is configured to send logs to a remote log host"][file] = \
                run_command(cmd_split(f"grep ^*.*[^I][^I]*@ {file}"))[0]
            self.parentDict["Ensure remote rsyslog messages are only accepted on designated log hosts."][file] = \
                {'ModLoad': run_command(cmd_split(f"grep '$ModLoad imtcp' {file}"))[0],
                        'InputTCPServerRun': run_command(cmd_split(f"grep '$InputTCPServerRun' {file}"))[0]}
        if os.path.exists('/etc/systemd/journald.conf'):
            self.parentDict["Ensure journald is configured to send logs to rsyslog"] = \
                run_command(cmd_split("grep -e ^\s*ForwardToSyslog /etc/systemd/journald.conf"))[0]
            self.parentDict["Ensure journald is configured to compress large log files"] = \
                run_command(cmd_split("grep -e ^\s*Compress /etc/systemd/journald.conf"))[0]
            self.parentDict["Ensure journald is configured to write logfiles to persistent disk"] = \
                run_command(cmd_split("grep -e ^\s*Storage /etc/systemd/journald.conf"))[0]
        else:
            out = "/etc/systemd/journald.conf doesn't exist"
            self.parentDict["Ensure journald is configured to send logs to rsyslog"] = out
            self.parentDict["Ensure journald is configured to compress large log files"] = out
            self.parentDict["Ensure journald is configured to write logfiles to persistent disk"] = out
        self.parentDict["Ensure permissions on all logfiles are configured"] = \
            run_command(cmd_split("find /var/log/ -type f -perm /g+wx,o+rwx -exec ls -l '{}' +"))[0]
        # 4.3 -- Manual
        for file in logrotate_files:
            self.parentDict["Ensure logrotate is configured"] = \
                {file: run_command(cmd_split(f"cat {file}"))[0]}
        self.parentDict['Ensure cron daemon is enabled'] = self.__is_enabled('cron')
        for file in ['/etc/crontab', '/etc/cron.hourly', '/etc/cron.daily',
                     '/etc/cron.weekly', '/etc/cron.monthly', '/etc/cron.d']:
            self.parentDict[f"Ensure permissions on {file} are configured"] = self.__check_file_permissions(file)
        myDict = {}
        for file in ['/etc/cron.allow', '/etc/cron.deny', '/etc/at.allow', '/etc/at.deny']:
            if os.path.exists(file):
                myDict[file] = self.__check_file_permissions(file)
            else:
                myDict[file] = f"{file} doesn't exist"

        self.parentDict["Ensure at/cron is restricted to authorized users"] = myDict
        if os.path.exists('/etc/ssh/sshd_config'):
            self.parentDict["Ensure permissions on /etc/ssh/sshd_config are configured"] = \
                self.__check_file_permissions("/etc/ssh/sshd_config")
        else:
            self.parentDict["Ensure permissions on /etc/ssh/sshd_config are configured"] = \
                "File /etc/ssh/sshd_config doesn't exist"

        if os.path.exists('/etc/login.defs'):
            self.parentDict['Ensure password expiration is 365 days or less'] = \
                run_command(cmd_split("grep PASS_MAX_DAYS /etc/login.defs"))[0]
            self.parentDict['Ensure minimum days between password changes is 7 or more'] = \
                run_command(cmd_split("grep PASS_MIN_DAYS /etc/login.defs"))[0]
            self.parentDict['Ensure password expiration warning days is 7 or more'] = \
                run_command(cmd_split("grep PASS_WARN_AGE /etc/login.defs"))[0]
        else:
            out = "file /etc/login.defs doesn't exist"
            self.parentDict['Ensure password expiration is 365 days or less'] = out
            self.parentDict['Ensure minimum days between password changes is 7 or more'] = out
            self.parentDict['Ensure password expiration warning days is 7 or more'] = out

        # 5.4.1.4
        self.parentDict["Ensure inactive password lock is 30 days or less"] = \
            run_command(cmd_split("useradd -D"), [cmd_split("grep INACTIVE")])[0]
        self.parentDict["Ensure default group for the root account is GID 0"] = \
            run_command(cmd_split("grep ^root: /etc/passwd"), [cmd_split("cut -f4 -d:")])[0]

        # 5.5
        self.parentDict["Ensure root login is restricted to system console"] = \
            run_command(cmd_split("sudo cat /etc/securetty"))[0]

        # 5.6
        self.parentDict["Ensure access to the su command is restricted"] = \
            {'pam': run_command(cmd_split("grep pam_wheel.so /etc/pam.d/su"))[0],
             '/etc/group': run_command(cmd_split("grep wheel /etc/group"))[0]}


        for file in usr_grp_files:
            self.parentDict[f"Ensure permissions on {file} are configured"] = self.__check_file_permissions(file)

        sysfile_dict = {"Ensure no world writable files exist":
                            """df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002""",
                        "Ensure no unowned files or directories exist":
                            """df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser""",
                        "Ensure no ungrouped files or directories exist":
                            """ df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup""",
                        "Audit SUID executables":
                            """df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000""",
                        "Audit SGID executables":
                            """df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000"""
                        }

        for key, val in sysfile_dict.items():
            self.parentDict[key] = self.__execute_bash_script(val)

        self.parentDict["Ensure password fields are not empty"] = \
            self.__execute_bash_script("""sudo cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'""")

        for file in usr_grp_files[:3]:
            if 'shadow' in file:
                self.parentDict[f'Ensure no legacy "+" entries exist in {file}'] = \
                    run_command(cmd_split(f"sudo cat {file}"), [cmd_split("grep '^\+'")])[0]
            else:
                self.parentDict[f'Ensure no legacy "+" entries exist in {file}'] = \
                run_command(cmd_split(f"grep ^\+: {file}"))[0]


        #6.2.5
        root_uid = """cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'"""
        self.parentDict["Ensure root is the only UID 0 account"] = self.__execute_bash_script(root_uid)

        # 6.2.6
        self.parentDict["Ensure root PATH Integrity"] = self.__execute_bash_script(root_path_integrity_script)

        # 6.2.7

        self.parentDict["Ensure all users' home directories exist"] = self.__execute_bash_script(home_dir_exist)

        # 6.2.8
        self.parentDict["Ensure users' home directories permissions are 750 or more restrictive"] = \
            self.__execute_bash_script(home_dir_perm)

        # 6.2.9
        self.parentDict["Ensure users own their home directories"] = self.__execute_bash_script(home_dir_owner)

        # 6.2.10
        self.parentDict["Ensure users' dot files are not group or world writable"] = \
            self.__execute_bash_script(dot_files_writable)

        # 6.2.11
        self.parentDict["Ensure no users have .forward files"] = \
            self.__execute_bash_script(users_have_fwdfiles)

        # 6.1.12
        self.parentDict["Ensure no users have .netrc files"] = \
            self.__execute_bash_script(users_have_netrcfiles)

        # 6.2.13
        self.parentDict["Ensure users' .netrc Files are not group or world accessible"] = \
            self.__execute_bash_script(users_netrcfiles_writable)

        # 6.2.14
        self.parentDict["Ensure no users have .rhosts files"] = self.__execute_bash_script(users_rhosts_files)

        # 6.2.15
        self.parentDict["Ensure all groups in /etc/passwd exist in /etc/group"] = \
            self.__execute_bash_script(files_exist)

        # 6.2.16
        self.parentDict["Ensure no duplicate UIDs exist"] = self.__execute_bash_script(duplicate_uids)

        # 6.2.17
        self.parentDict["Ensure no duplicate GIDs exist"] = self.__execute_bash_script(duplicate_gids)

        # 6.2.18
        self.parentDict["Ensure no duplicate user names exist"] = self.__execute_bash_script(duplicate_users)

        # 6.2.19
        self.parentDict["Ensure no duplicate group names exist"] = self.__execute_bash_script(duplicate_groups)

        # 6.2.20
        self.parentDict["Ensure shadow group is empty"] = {
            "grep": run_command(cmd_split(" grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group"))[0],
            "awk": self.__execute_bash_script("""awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd""")}
        return self.parentDict
if __name__ == "__main__":
    if 'sbin' not in os.environ["PATH"]:
        os.environ["PATH"] += ":/sbin:/usr/sbin:/usr/local/sbin"
    if os.path.exists('/etc/os-release'):
        operating_system = run_command(cmd_split('cat /etc/os-release'), [cmd_split('grep -i "pretty_name"')])[0]
    else:
        try:
            operating_system = run_command('hostnamectl', [cmd_split('grep -i "operating system"')])[0]
        except FileNotFoundError as e:
            print("Unable to determine the Operating system, please choose an option from the below list")
            operating_system = ask_user()
            pass
    benchmark = Benchmark(operating_system)
    result_dict = benchmark.os_checks()
    if 'ubuntu' in operating_system.lower():
        parent_dict = {1:
			       {'Initial Setup':
				    {1.1:
					 {'Filesystem Configuration':
					      {"1.1.1.1":
						   {"Ensure mounting of cramfs filesystems is disabled":
							result_dict["Ensure mounting of cramfs filesystems is disabled"]},
					       "1.1.1.2":
						    {"Ensure mounting of freevxfs filesystems is disabled":
							result_dict["Ensure mounting of freevxfs filesystems is disabled"]},
						"1.1.1.3":
						    {"Ensure mounting of jffs2 filesystems is disabled":
							result_dict["Ensure mounting of jffs2 filesystems is disabled"]},
						"1.1.1.4":
						    {"Ensure mounting of hfs filesystems is disabled":
							result_dict["Ensure mounting of hfs filesystems is disabled"]},
						"1.1.1.5":
						    {"Ensure mounting of hfsplus filesystems is disabled":
							result_dict["Ensure mounting of hfsplus filesystems is disabled"]},
						"1.1.1.6":
						    {"Ensure mounting of udf filesystems is disabled":
							result_dict["Ensure mounting of udf filesystems is disabled"]},
						"1.1.2":
						    {"Ensure separate partition exists for /tmp":
							result_dict["Ensure separate partition exists for /tmp"]},
						"1.1.3":
						    {"Ensure nodev option set on /tmp partition":
							result_dict["Ensure nodev option set on /tmp partition"]},
						"1.1.4":
						    {"Ensure nosuid option set on /tmp partition":
							result_dict["Ensure nosuid option set on /tmp partition"]},
						"1.1.5":
						    {"Ensure separate partition exists for /var":
							result_dict["Ensure separate partition exists for /var"]},
						"1.1.6":
						    {"Ensure separate partition exists for /var/tmp":
							result_dict["Ensure separate partition exists for /var/tmp"]},
						"1.1.7":
						    {"Ensure nodev option set on /var/tmp partition":
							result_dict["Ensure nodev option set on /var/tmp partition"]},
						"1.1.8":
						    {"Ensure nosuid option set on /var/tmp partition":
							result_dict["Ensure nosuid option set on /var/tmp partition"]},
						"1.1.9":
						    {"Ensure noexec option set on /var/tmp partition":
							result_dict["Ensure noexec option set on /var/tmp partition"]},
						"1.1.10":
						    {"Ensure separate partition exists for /var/log":
							result_dict["Ensure separate partition exists for /var/log"]},
						"1.1.11":
						    {"Ensure separate partition exists for /var/log/audit":
							result_dict["Ensure separate partition exists for /var/log/audit"]},
						"1.1.12":
						    {"Ensure separate partition exists for /home":
							result_dict["Ensure separate partition exists for /home"]},
						"1.1.13":
						    {"Ensure nodev option set on /home partition":
							result_dict["Ensure nodev option set on /home partition"]},
						"1.1.14":
						    {"Ensure nodev option set on /dev/shm partition":
							result_dict["Ensure nodev option set on /dev/shm partition"]},
						"1.1.15":
						    {"Ensure nosuid option set on /dev/shm partition":
							result_dict["Ensure nosuid option set on /dev/shm partition"]},
						"1.1.16":
						    {"Ensure noexec option set on /dev/shm partition":
							result_dict["Ensure noexec option set on /dev/shm partition"]},
						"1.1.17":
						    {"Ensure nodev option set on removable media partitions":
							result_dict["Ensure nodev option set on removable media partitions"]},
						"1.1.18":
						    {"Ensure nosuid option set on removable media partitions":
							result_dict["Ensure nosuid option set on removable media partitions"]},
						"1.1.19":
						    {"Ensure noexec option set on removable media partitions":
							result_dict["Ensure noexec option set on removable media partitions"]},
						"1.1.20":
						    {"Ensure sticky bit is set on all world-writable directories":
							result_dict["Ensure sticky bit is set on all world-writable directories"]},
						"1.1.21":
						    {"Disable Automounting":
							result_dict["Disable Automounting"]}}}},
				    1.2:
					{'Configure Software Updates':
					     {"1.2.1":
						  {"Ensure package manager repositories are configured":
						       result_dict["Ensure package manager repositories are configured"]},
					      "1.2.2":
						  {"Ensure GPG keys are configured":
						       result_dict["Ensure GPG keys are configured"]}}},
				    1.3:
					{'Filesystem Integrity Checking':
					     {"1.3.1":
						  {"Ensure AIDE is installed":
						       result_dict["Ensure AIDE is installed"]},
					      "1.3.2":
						  {"Ensure filesystem integrity is regularly checked":
						       result_dict["Ensure filesystem integrity is regularly checked"]}}},
				    1.4: {'Secure Boot settings':
					      {"1.4.1":
						   {"Ensure permissions on bootloader config are configured":
							result_dict["Ensure permissions on bootloader config are configured"]},
					       "1.4.2":
						   {"Ensure bootloader password is set":
							result_dict["Ensure bootloader password is set"]},
					       "1.4.3":
						   {"Ensure authentication required for single user mode":
							result_dict["Ensure authentication required for single user mode"]}}},
				    1.5: {'Additional Process Hardening':
					      {"1.5.1":
						   {"Ensure core dumps are restricted":
							result_dict["Ensure core dumps are restricted"]},
					       "1.5.2":
						   {"Ensure XD/NX support is enabled":
							result_dict["Ensure XD/NX support is enabled"]},
					       "1.5.3":
						   {"Ensure address space layout randomization (ASLR) is enabled":
							result_dict["Ensure address space layout randomization (ASLR) is enabled"]},
					       "1.5.4":
						   {"Ensure prelink is disabled":
							result_dict["Ensure prelink is disabled"]}}},
				    1.6: {'Mandatory Access Control':
					      {"1.6.1.1":
						   {"Ensure SELinux is not disabled in bootloader configuration":
							result_dict["Ensure SELinux is not disabled in bootloader configuration"]},
					       "1.6.1.2":
						   {"Ensure the SELinux state is enforcing":
							result_dict["Ensure the SELinux state is enforcing"]},
					       "1.6.1.3":
						   {"Ensure SELinux policy is configured":
							result_dict["Ensure SELinux policy is configured"]},
					       "1.6.1.4":
						   {"Ensure no unconfined daemons exist":
							result_dict["Ensure no unconfined daemons exist"]},
					       "1.6.2.1":
						   {"Ensure AppArmor is not disabled in bootloader configuration":
							result_dict["Ensure AppArmor is not disabled in bootloader configuration"]},
					   #    "1.6.2.2":
					   #        {"Ensure all AppArmor Profiles are enforcing":
					   #             result_dict["Ensure all AppArmor Profiles are enforcing"]},
					       "1.6.3":
						   {"Ensure SELinux or AppArmor are installed":
							result_dict["Ensure SELinux or AppArmor are installed"]}}},
				    1.7: {'Warning Banners':
					      {"1.7.1.1":
						   {"Ensure message of the day is configured properly":
							result_dict["Ensure message of the day is configured properly"]},
					       "1.7.1.2":
						   {"Ensure local login warning banner is configured properly":
							result_dict["Ensure local login warning banner is configured properly"]},
					       "1.7.1.3":
						   {"Ensure remote login warning banner is configured properly":
							result_dict["Ensure remote login warning banner is configured properly"]},
					       "1.7.1.4":
						   {"Ensure permissions on /etc/motd are configured":
							result_dict["Ensure permissions on /etc/motd are configured"]},
					       "1.7.1.5":
						   {"Ensure permissions on /etc/issue are configured":
							result_dict["Ensure permissions on /etc/issue are configured"]},
					       "1.7.1.6":
						   {"Ensure permissions on /etc/issue.net are configured":
							result_dict["Ensure permissions on /etc/issue.net are configured"]},
					       "1.7.2":
						   {"Ensure GDM login banner is configured":
							result_dict["Ensure GDM login banner is configured"]},
					       "1.8":
						   {"Ensure updates, patches, and additional security software are installed":
							result_dict["Ensure updates, patches, and additional security software are installed"]}}}},
			   2: {'Services':
				   {2.1:
					{'inetd_services':
					     {"2.1.1":
						  {"Ensure chargen services are not enabled":
						       result_dict["Ensure chargen services are not enabled"]},
					      "2.1.2":
						  {"Ensure daytime services are not enabled":
						       result_dict["Ensure daytime services are not enabled"]},
					      "2.1.3":
						  {"Ensure discard services are not enabled":
						       result_dict["Ensure discard services are not enabled"]},
					      "2.1.4":
						  {"Ensure echo services are not enabled":
						       result_dict["Ensure echo services are not enabled"]},
					      "2.1.5":
						  {"Ensure time services are not enabled":
						       result_dict["Ensure time services are not enabled"]},
					      "2.1.6":
						  {"Ensure rsh server is not enabled":
						       result_dict["Ensure rsh server is not enabled"]},
					      "2.1.7":
						  {"Ensure talk server is not enabled":
						       result_dict["Ensure talk server is not enabled"]},
					      "2.1.8":
						  {"Ensure telnet server is not enabled":
						       result_dict["Ensure telnet server is not enabled"]},
					      "2.1.9":
						  {"Ensure tftp server is not enabled":
						       result_dict["Ensure tftp server is not enabled"]},
					      "2.1.10":
						  {"Ensure xinetd is not enabled":
						       result_dict["Ensure xinetd is not enabled"]},
					      "2.1.11":
						  {"Ensure openbsd-inetd is not installed":
						       result_dict["Ensure openbsd-inetd is not installed"]}}},
					    2.2:
						{'Special Purpose Services':
						     {"2.2.1.1":
							  {"Ensure time synchronization is in use":
							       result_dict["Ensure time synchronization is in use"]},
						      "2.2.1.2":
							  {"Ensure ntp is configured":
							       result_dict["Ensure ntp is configured"]},
						      "2.2.1.3":
							  {"Ensure chrony is configured":
							       result_dict["Ensure chrony is configured"]},
						      "2.2.2":
							  {"Ensure X Window System is not installed":
								result_dict["Ensure X Window System is not installed"]},
						      "2.2.3":
							  {"Ensure Avahi Server is not enabled":
							       result_dict["Ensure Avahi Server is not enabled"]},
						      "2.2.4":
							  {"Ensure CUPS is not enabled":
							       result_dict["Ensure CUPS is not enabled"]},
						      "2.2.5":
							  {"Ensure DHCP Server is not enabled":
							       result_dict["Ensure DHCP Server is not enabled"]},
						      "2.2.6":
							  {"Ensure LDAP server is not enabled":
							       result_dict["Ensure LDAP server is not enabled"]},
						      "2.2.7":
							  {"Ensure NFS and RPC are not enabled":
							       result_dict["Ensure NFS and RPC are not enabled"]},
						      "2.2.8":
							  {"Ensure DNS Server is not enabled":
							       result_dict["Ensure DNS Server is not enabled"]},
						      "2.2.9":
							  {"Ensure FTP Server is not enabled":
							       result_dict["Ensure FTP Server is not enabled"]},
						      "2.2.10":
							  {"Ensure HTTP server is not enabled":
							       result_dict["Ensure HTTP server is not enabled"]},
						      "2.2.11":
							  {"Ensure IMAP and POP3 server is not enabled":
							       result_dict["Ensure IMAP and POP3 server is not enabled"]},
						      "2.2.12":
							  {"Ensure Samba is not enabled":
							       result_dict["Ensure Samba is not enabled"]},
						      "2.2.13":
							  {"Ensure HTTP Proxy Server is not enabled":
							       result_dict["Ensure HTTP Proxy Server is not enabled"]},
						      "2.2.14":
							  {"Ensure SNMP Server is not enabled":
							       result_dict["Ensure SNMP Server is not enabled"]},
						      "2.2.15":
							  {"Ensure mail transfer agent is configured for local-only mode":
							       result_dict["Ensure mail transfer agent is configured for local-only mode"]},
						      "2.2.16":
							  {"Ensure rsync service is not enabled":
							       result_dict["Ensure rsync service is not enabled"]},
						      "2.2.17":
							  {"Ensure NIS Server is not enabled":
							       result_dict["Ensure NIS Server is not enabled"]}}},
					    2.3: {
						'Service Clients':
						    {"2.3.1":
							 {"Ensure NIS Client is not installed":
							      result_dict["Ensure NIS Client is not installed"]},
						     "2.3.2":
							 {"Ensure rsh client is not installed":
							      result_dict["Ensure rsh client is not installed"]},
						     "2.3.3":
							 {"Ensure talk client is not installed":
							      result_dict["Ensure talk client is not installed"]},
						     "2.3.4":
							 {"Ensure telnet client is not installed":
							      result_dict["Ensure telnet client is not installed"]},
						     "2.3.5":
							 {"Ensure LDAP client is not installed":
							      result_dict["Ensure LDAP client is not installed"]}}}}},
			   3:
			       {3.1:
				    {"Network Parameters(Host Only)":
					 {"3.1.1":
					      {"Ensure IP forwarding is disabled":
						   result_dict["Ensure IP forwarding is disabled"]},
					  "3.1.2":
					       {"Ensure packet redirect sending is disabled":
						    result_dict["Ensure packet redirect sending is disabled"]}
					  }},
			       3.2:
				   {"Network Parameters(Host and router)":
					{"3.2.1":
					     {"Ensure source routed packets are not accepted":
						  result_dict["Ensure source routed packets are not accepted"]},
					 "3.2.2":
					     {"Ensure ICMP redirects are not accepted":
						  result_dict["Ensure ICMP redirects are not accepted"]},
					 "3.2.3":
					     {"Ensure secure ICMP redirects are not accepted":
						  result_dict["Ensure secure ICMP redirects are not accepted"]},
					 "3.2.4":
					     {"Ensure suspicious packets are logged":
						  result_dict["Ensure suspicious packets are logged"]},
					 "3.2.5":
					     {"Ensure broadcast ICMP requests are ignored":
						  result_dict["Ensure broadcast ICMP requests are ignored"]},
					 "3.2.6":
					     {"Ensure bogus ICMP responses are ignored":
						  result_dict["Ensure bogus ICMP responses are ignored"]},
					 "3.2.7":
					     {"Ensure Reverse Path Filtering is enabled":
						  result_dict["Ensure Reverse Path Filtering is enabled"]},
					 "3.2.8":
					     {"Ensure TCP SYN Cookies is enabled":
						  result_dict["Ensure TCP SYN Cookies is enabled"]},
					 }},
			       3.3:
				    {"IPV6":
					 {"3.3.1":
					      {"Ensure IPv6 router advertisements are not accepted":
						   result_dict["Ensure IPv6 router advertisements are not accepted"]},
					  "3.3.2":
					      {"Ensure IPv6 redirects are not accepted":
						   result_dict["Ensure IPv6 redirects are not accepted"]},
					  "3.3.3":
					      {"Ensure IPv6 is disabled":
						   result_dict["Ensure IPv6 is disabled"]},
					  }},
			       3.4: {"TCP Wrappers":
					 {"3.4.1":
					      {"Ensure TCP Wrappers is installed":
						   result_dict["Ensure TCP Wrappers is installed"]},
					  "3.4.2":
					      {"Ensure /etc/hosts.allow is configured":
						   result_dict["Ensure /etc/hosts.allow is configured"]},
					  "3.4.3":
					      {"Ensure /etc/hosts.deny is configured":
						   result_dict["Ensure /etc/hosts.deny is configured"]},
					  "3.4.4":
					      {"Ensure permissions on /etc/hosts.allow are configured":
						   result_dict["Ensure permissions on /etc/hosts.allow are configured"]},
					  "3.4.5":
					      {"Ensure permissions on /etc/hosts.deny are configured":
						   result_dict["Ensure permissions on /etc/hosts.deny are configured"]}
					 }},
			       3.5: {"Uncommon Network Protocols":
					 {"3.5.1":
					      {"Ensure DCCP is disabled":
						   result_dict["Ensure DCCP is disabled"]},
					  "3.5.2":
					      {"Ensure SCTP is disabled":
						   result_dict["Ensure SCTP is disabled"]},
					  "3.5.3":
					      {"Ensure RDS is disabled":
						   result_dict["Ensure RDS is disabled"]},
					  "3.5.4":
					      {"Ensure TIPC is disabled":
						   result_dict["Ensure TIPC is disabled"]}
					  }},
			       3.6: {"Firewall Configuration":
					 {"3.6.1":
					      {"Ensure iptables is installed":
						   result_dict["Ensure iptables is installed"]},
					  "3.6.2":
					      {"Ensure default deny firewall policy":
						   result_dict["Ensure default deny firewall policy"]},
					  "3.6.3":
					      {"Ensure loopback traffic is configured":
						   result_dict["Ensure loopback traffic is configured"]},
					  "3.6.4":
					      {"Ensure outbound and established connections are configured":
						   result_dict["Ensure outbound and established connections are configured"]},
					  "3.6.5":
					      {"Ensure firewall rules exist for all open ports":
						   result_dict["Ensure firewall rules exist for all open ports"]}
					  }},
			       3.7: {"Ensure wireless interfaces are disabled":
					 result_dict["Ensure wireless interfaces are disabled"]}},
			   4:
			       {4.1:
				   {"Configure System Accounting":
					{"4.1.1.1":
					     {"Ensure audit log storage size is configured":
						  result_dict["Ensure audit log storage size is configured"]},
					 "4.1.1.2":
					     {"Ensure system is disabled when audit logs are full":
						  result_dict["Ensure system is disabled when audit logs are full"]},
					 "4.1.1.3":
					     {"Ensure audit logs are not automatically deleted":
						  result_dict["Ensure audit logs are not automatically deleted"]},
					 "4.1.2":
					     {"Ensure auditd service is enabled":
						  result_dict["Ensure auditd service is enabled"]},
					 "4.1.3":
					     {"Ensure auditing for processes that start prior to auditd is enabled":
						  result_dict["Ensure auditing for processes that start prior to auditd is enabled"]},
					 "4.1.4":
					     {"Ensure events that modify date and time information are collected":
						  result_dict["Ensure events that modify date and time information are collected"]},
					 "4.1.5":
					     {"Ensure events that modify user/group information are collected":
						  result_dict["Ensure events that modify user/group information are collected"]},
					 "4.1.6":
					     {"Ensure events that modify the system's network environment are collected":
						  result_dict["Ensure events that modify the system's network environment are collected"]},
					 "4.1.7":
					     {"Ensure events that modify the system's Mandatory Access Controls are collected":
						  result_dict["Ensure events that modify the system's Mandatory Access Controls are collected"]},
					 "4.1.8":
					     {"Ensure login and logout events are collected":
						  result_dict["Ensure login and logout events are collected"]},
					 "4.1.9":
					     {"Ensure session initiation information is collected":
						  result_dict["Ensure session initiation information is collected"]},
					 "4.1.10":
					     {"Ensure discretionary access control permission modification events are collected":
						  result_dict["Ensure discretionary access control permission modification events are collected"]},
					 "4.1.11":
					     {"Ensure unsuccessful unauthorized file access attempts are collected":
						  result_dict["Ensure unsuccessful unauthorized file access attempts are collected"]},
					 "4.1.12":
					     {"Ensure use of privileged commands is collected":
						  result_dict["Ensure use of privileged commands is collected"]},
					 "4.1.13":
					     {"Ensure successful file system mounts are collected":
						  result_dict["Ensure successful file system mounts are collected"]},
					 "4.1.14":
					     {"Ensure file deletion events by users are collected":
						  result_dict["Ensure file deletion events by users are collected"]},
					 "4.1.15":
					     {"Ensure changes to system administration scope (sudoers) is collected":
						  result_dict["Ensure changes to system administration scope (sudoers) is collected"]},
					 "4.1.16":
					     {"Ensure system administrator actions (sudolog) are collected":
						  result_dict["Ensure system administrator actions (sudolog) are collected"]},
					 "4.1.17":
					     {"Ensure kernel module loading and unloading is collected":
						  result_dict["Ensure kernel module loading and unloading is collected"]},
					 "4.1.18":
					     {"Ensure the audit configuration is immutable":
						  result_dict["Ensure the audit configuration is immutable"]}
					 }},
			       4.2:
				   {"Configure Logging":
					{"4.2.1.1":
					     {"Ensure rsyslog Service is enabled":
						  result_dict["Ensure rsyslog Service is enabled"]},
					 "4.2.1.2":
					     {"Ensure logging is configured":
						  result_dict["Ensure logging is configured"]},
					 "4.2.1.3":
					     {"Ensure rsyslog default file permissions configured":
						  result_dict["Ensure rsyslog default file permissions configured"]},
					 "4.2.1.4":
					     {"Ensure rsyslog is configured to send logs to a remote log host":
						  result_dict["Ensure rsyslog is configured to send logs to a remote log host"]},
					 "4.2.1.5":
					     {"Ensure remote rsyslog messages are only accepted on designated log hosts.":
						  result_dict["Ensure remote rsyslog messages are only accepted on designated log hosts."]},
					 "4.2.2.1":
					     {"Ensure syslog-ng service is enabled":
						  result_dict["Ensure syslog-ng service is enabled"]},
					 "4.2.2.2":
					     {"Ensure logging is configured":
						  result_dict["Ensure logging is configured"]},
					 "4.2.2.3":
					     {"Ensure syslog-ng default file permissions configured":
						  result_dict["Ensure syslog-ng default file permissions configured"]},
					 "4.2.2.4":
					     {"Ensure syslog-ng is configured to send logs to a remote log host":
						  result_dict["Ensure syslog-ng is configured to send logs to a remote log host"]},
					 "4.2.2.5":
					     {"Ensure remote syslog-ng messages are only accepted on designated log hosts":
						  result_dict["Ensure remote syslog-ng messages are only accepted on designated log hosts"]},
					 "4.2.3":
					     {"Ensure rsyslog or syslog-ng is installed":
						  result_dict["Ensure rsyslog or syslog-ng is installed"]},
					 "4.2.4":
					     {"Ensure permissions on all logfiles are configured":
						  result_dict["Ensure permissions on all logfiles are configured"]},
					 "4.3":
					     {"Ensure logrotate is configured":
						  result_dict["Ensure logrotate is configured"]},
					 }}},
			   5:
			       {5.1:
				    {"Configure cron":
					 {"5.1.1":
					      {"Ensure cron daemon is enabled":
						   result_dict["Ensure cron daemon is enabled"]},
					  "5.1.2":
					      {"Ensure permissions on /etc/crontab are configured":
						   result_dict["Ensure permissions on /etc/crontab are configured"]},
					  "5.1.3":
					      {"Ensure permissions on /etc/cron.hourly are configured":
						   result_dict["Ensure permissions on /etc/cron.hourly are configured"]},
					  "5.1.4":
					      {"Ensure permissions on /etc/cron.daily are configured":
						   result_dict["Ensure permissions on /etc/cron.daily are configured"]},
					  "5.1.5":
					      {"Ensure permissions on /etc/cron.weekly are configured":
						   result_dict["Ensure permissions on /etc/cron.weekly are configured"]},
					  "5.1.6":
					      {"Ensure permissions on /etc/cron.monthly are configured":
						   result_dict["Ensure permissions on /etc/cron.monthly are configured"]},
					  "5.1.7":
					      {"Ensure permissions on /etc/cron.d are configured":
						   result_dict["Ensure permissions on /etc/cron.d are configured"]},
					  "5.1.8":
					      {"Ensure at/cron is restricted to authorized users":
						   result_dict["Ensure at/cron is restricted to authorized users"]},
					  }},
			       5.2:
				   {"SSH Server configuration":
					{"5.2.1":
					      {"Ensure permissions on /etc/ssh/sshd_config are configured":
						   result_dict["Ensure permissions on /etc/ssh/sshd_config are configured"]},
					 "5.2.2":
					     {"Ensure SSH Protocol is set to 2":
						  result_dict["Ensure SSH Protocol is set to 2"]},

					 "5.2.3":
					     {"Ensure SSH LogLevel is set to INFO":
						  result_dict["Ensure SSH LogLevel is set to INFO"]},

					 "5.2.4":
					     {"Ensure SSH X11 forwarding is disabled":
						  result_dict["Ensure SSH X11 forwarding is disabled"]},

					 "5.2.5":
					     {"Ensure SSH MaxAuthTries is set to 4 or less":
						  result_dict["Ensure SSH MaxAuthTries is set to 4 or less"]},

					 "5.2.6":
					     {"Ensure SSH IgnoreRhosts is enabled":
						  result_dict["Ensure SSH IgnoreRhosts is enabled"]},

					 "5.2.7":
					     {"Ensure SSH HostbasedAuthentication is disabled":
						  result_dict["Ensure SSH HostbasedAuthentication is disabled"]},
					 "5.2.8":
					     {"Ensure SSH root login is disabled":
						  result_dict["Ensure SSH root login is disabled"]},
					 "5.2.9":
					     {"Ensure SSH PermitEmptyPasswords is disabled":
						  result_dict["Ensure SSH PermitEmptyPasswords is disabled"]},
					 "5.2.10":
					     {"Ensure SSH PermitUserEnvironment is disabled":
						  result_dict["Ensure SSH PermitUserEnvironment is disabled"]},
					 "5.2.11":
					     {"Ensure only approved MAC algorithms are used":
						  result_dict["Ensure only approved MAC algorithms are used"]},
					 "5.2.12":
					     {"Ensure SSH Idle Timeout Interval is configured":
						  result_dict["Ensure SSH Idle Timeout Interval is configured"]},
					 "5.2.13":
					     {"Ensure SSH LoginGraceTime is set to one minute or less":
						  result_dict["Ensure SSH LoginGraceTime is set to one minute or less"]},
					 "5.2.14":
					     {"Ensure SSH access is limited":
						  result_dict["Ensure SSH access is limited"]},
					 "5.2.15":
					     {"Ensure SSH warning banner is configured":
						  result_dict["Ensure SSH warning banner is configured"]}
					 }},
			       5.3:
				    {"Configure PAM":
					 {"5.3.1":
					      {"Ensure password creation requirements are configured":
						   result_dict["Ensure password creation requirements are configured"]},
					  "5.3.2":
					      {"Ensure lockout for failed password attempts is configured":
						   result_dict["Ensure lockout for failed password attempts is configured"]},
					  "5.3.3":
					      {"Ensure password reuse is limited":
						   result_dict["Ensure password reuse is limited"]},
					  "5.3.4":
					      {"Ensure password hashing algorithm is SHA-512":
						   result_dict["Ensure password hashing algorithm is SHA-512"]},
					  }},
			       5.4:
				    {"User Accounts and Environment":
					 {"5.4.1.1":
					      {"Ensure password expiration is 365 days or less":
						   result_dict["Ensure password expiration is 365 days or less"]},
					  "5.4.1.2":
					      {"Ensure minimum days between password changes is 7 or more":
						   result_dict["Ensure minimum days between password changes is 7 or more"]},
					  "5.4.1.3":
					      {"Ensure password expiration warning days is 7 or more":
						   result_dict["Ensure password expiration warning days is 7 or more"]},
					  "5.4.1.4":
					      {"Ensure inactive password lock is 30 days or less":
						   result_dict["Ensure inactive password lock is 30 days or less"]},
					  "5.4.1.5":
					      {"Ensure all users last password change date is in the past":
						   result_dict["Ensure all users last password change date is in the past"]},
					  "5.4.2":
					      {"Ensure system accounts are non-login":
						   result_dict["Ensure system accounts are non-login"]},
					  "5.4.3":
					      {"Ensure default group for the root account is GID 0":
						   result_dict["Ensure default group for the root account is GID 0"]},
					  "5.4.4":
					      {"Ensure default user umask is 027 or more restrictive":
						   result_dict["Ensure default user umask is 027 or more restrictive"]},
					  "5.4.5":
					      {"Ensure default user shell timeout is 900 seconds or less":
						   result_dict["Ensure default user shell timeout is 900 seconds or less"]},
					  "5.5":
					      {"Ensure root login is restricted to system console":
						   result_dict["Ensure root login is restricted to system console"]},
					  "5.6":
					      {"Ensure access to the su command is restricted":
						   result_dict["Ensure access to the su command is restricted"]}
					  }}},
			   6:
			       {6.1:
				    {"System File Permissions":
					 {"6.1.1":
					      {"Audit system file permissions":
						   result_dict["Audit system file permissions"]},
					  "6.1.2":
					      {"Ensure permissions on /etc/passwd are configured":
						   result_dict["Ensure permissions on /etc/passwd are configured"]},
					  "6.1.3":
					      {"Ensure permissions on /etc/shadow are configured":
						   result_dict["Ensure permissions on /etc/shadow are configured"]},
					  "6.1.4":
					      {"Ensure permissions on /etc/group are configured":
						   result_dict["Ensure permissions on /etc/group are configured"]},
					  "6.1.5":
					      {"Ensure permissions on /etc/gshadow are configured":
						   result_dict["Ensure permissions on /etc/gshadow are configured"]},
					  "6.1.6":
					      {"Ensure permissions on /etc/passwd- are configured":
						   result_dict["Ensure permissions on /etc/passwd- are configured"]},
					  "6.1.7":
					      {"Ensure permissions on /etc/shadow- are configured":
						   result_dict["Ensure permissions on /etc/shadow- are configured"]},
					  "6.1.8":
					      {"Ensure permissions on /etc/group- are configured":
						   result_dict["Ensure permissions on /etc/group- are configured"]},
					  "6.1.9":
					      {"Ensure permissions on /etc/gshadow- are configured":
						   result_dict["Ensure permissions on /etc/gshadow- are configured"]},
					  "6.1.10":
					      {"Ensure no world writable files exist":
						   result_dict["Ensure no world writable files exist"]},
					  "6.1.11":
					      {"Ensure no unowned files or directories exist":
						   result_dict["Ensure no unowned files or directories exist"]},
					  "6.1.12":
					      {"Ensure no ungrouped files or directories exist":
						   result_dict["Ensure no ungrouped files or directories exist"]},
					  "6.1.13":
					      {"Audit SUID executables":
						   result_dict["Audit SUID executables"]},
					  "6.1.14":
					      {"Audit SGID executables":
						   result_dict["Audit SGID executables"]},
					  }},
			       6.2:
				   {"User and Group Settings":
					{"6.2.1":
					      {"Ensure password fields are not empty":
						   result_dict["Ensure password fields are not empty"]},
					 "6.2.2":
					     {'Ensure no legacy "+" entries exist in /etc/passwd':
						  result_dict['Ensure no legacy "+" entries exist in /etc/passwd']},
					 "6.2.3":
					     {'Ensure no legacy "+" entries exist in /etc/shadow':
						  result_dict['Ensure no legacy "+" entries exist in /etc/shadow']},
					 "6.2.4":
					     {'Ensure no legacy "+" entries exist in /etc/group':
						  result_dict['Ensure no legacy "+" entries exist in /etc/group']},
					 "6.2.5":
					     {"Ensure root is the only UID 0 account":
						  result_dict["Ensure root is the only UID 0 account"]},
					 "6.2.6":
					     {"Ensure root PATH Integrity":
						  result_dict["Ensure root PATH Integrity"]},
					 "6.2.7":
					     {"Ensure all users' home directories exist":
						  result_dict["Ensure all users' home directories exist"]},
					 "6.2.8":
					     {"Ensure users' home directories permissions are 750 or more restrictive":
						  result_dict["Ensure users' home directories permissions are 750 or more restrictive"]},
					 "6.2.9":
					     {"Ensure users own their home directories":
						  result_dict["Ensure users own their home directories"]},
					 "6.2.10":
					     {"Ensure users' dot files are not group or world writable":
						  result_dict["Ensure users' dot files are not group or world writable"]},
					 "6.2.11":
					     {"Ensure no users have .forward files":
						  result_dict["Ensure no users have .forward files"]},
					 "6.2.12":
					     {"Ensure no users have .netrc files":
						  result_dict["Ensure no users have .netrc files"]},
					 "6.2.13":
					     {"Ensure users' .netrc Files are not group or world accessible":
						  result_dict["Ensure users' .netrc Files are not group or world accessible"]},
					 "6.2.14":
					     {"Ensure no users have .rhosts files":
						  result_dict["Ensure no users have .rhosts files"]},
					 "6.2.15":
					     {"Ensure all groups in /etc/passwd exist in /etc/group":
						  result_dict["Ensure all groups in /etc/passwd exist in /etc/group"]},
					 "6.2.16":
					     {"Ensure no duplicate UIDs exist":
						  result_dict["Ensure no duplicate UIDs exist"]},
					 "6.2.17":
					     {"Ensure no duplicate GIDs exist":
						  result_dict["Ensure no duplicate GIDs exist"]},
					 "6.2.18":
					     {"Ensure no duplicate user names exist":
						  result_dict["Ensure no duplicate user names exist"]},
					 "6.2.19":
					     {"Ensure no duplicate group names exist":
						  result_dict["Ensure no duplicate group names exist"]},
					 "6.2.20":
					     {"Ensure shadow group is empty":
						  result_dict["Ensure shadow group is empty"]},
					 }}}}
    else:
        parent_dict = {1: {'Initial Setup':
				   {1.1:
					{'Filesystem Configuration':
					     {"1.1.1":
						  {'Disable unused filesystems':
						       {'1.1.1.1': {
							   'Ensure mounting of cramfs filesystems is disabled': result_dict[
							       'Ensure mounting of cramfs filesystems is disabled']},
							'1.1.1.2': {
							    'Ensure mounting of vFAT filesystems is limited': result_dict[
								'Ensure mounting of vFAT filesystems is limited']},
							'1.1.1.3': {
							    'Ensure mounting of squashfs filesystems is disabled': result_dict[
								'Ensure mounting of squashfs filesystems is disabled']},
							'1.1.1.4': {
							    'Ensure mounting of udf filesystems is disabled': result_dict[
								'Ensure mounting of udf filesystems is disabled']}}
						   },
					      '1.1.2': {'Ensure /tmp is configured': result_dict['Ensure /tmp is configured']},
					      '1.1.3': {'Ensure nodev option set on /tmp partition': result_dict[
						  'Ensure nodev option set on /tmp partition']},
					      '1.1.4': {'Ensure nosuid option set on /tmp partition': result_dict[
						  'Ensure nosuid option set on /tmp partition']},
					      '1.1.5': {'Ensure noexec option set on /tmp partition': result_dict[
						  'Ensure noexec option set on /tmp partition']},
					      '1.1.6': {'Ensure separate partition exists for /var': result_dict[
						  'Ensure separate partition exists for /var']},
					      '1.1.7': {'Ensure separate partition exists for /var/tmp': result_dict[
						  'Ensure separate partition exists for /var/tmp']},
					      '1.1.8': {'Ensure nodev option set on /var/tmp partition': result_dict[
						  'Ensure nodev option set on /var/tmp partition']},
					      '1.1.9': {'Ensure nosuid option set on /var/tmp partition': result_dict[
						  'Ensure nosuid option set on /var/tmp partition']},
					      '1.1.10': {'Ensure noexec option set on /var/tmp partition': result_dict[
						  'Ensure noexec option set on /var/tmp partition']},
					      '1.1.11': {'Ensure separate partition exists for /var/log': result_dict[
						  'Ensure separate partition exists for /var/log']},
					      '1.1.12': {'Ensure separate partition exists for /var/log/audit': result_dict[
						  'Ensure separate partition exists for /var/log/audit']},
					      '1.1.13': {'Ensure separate partition exists for /home': result_dict[
						  'Ensure separate partition exists for /home']},
					      '1.1.14': {'Ensure nodev option set on /home partition': result_dict[
						  'Ensure nodev option set on /home partition']},
					      '1.1.15': {'Ensure nodev option set on /dev/shm partition': result_dict[
						  'Ensure nodev option set on /dev/shm partition']},
					      '1.1.16': {'Ensure nosuid option set on /dev/shm partition': result_dict[
						  'Ensure nosuid option set on /dev/shm partition']},
					      '1.1.17': {'Ensure noexec option set on /dev/shm partition': result_dict[
						  'Ensure noexec option set on /dev/shm partition']},
					      '1.1.18': {'Ensure nodev option set on removable media partitions': result_dict[
						  'Ensure nodev option set on removable media partitions']},
					      '1.1.19': {'Ensure nosuid option set on removable media partitions': result_dict[
						  'Ensure nosuid option set on removable media partitions']},
					      '1.1.20': {'Ensure noexec option set on removable media partitions': result_dict[
						  'Ensure noexec option set on removable media partitions']},
					      '1.1.21': {
						  'Ensure sticky bit is set on all world-writable directories': result_dict[
						      'Ensure sticky bit is set on all world-writable directories']},
					      '1.1.22': {'Disable Automounting': result_dict['Disable Automounting']},
					      '1.1.23': {'Disable USB Storage': result_dict['Disable USB Storage']}
					      }
					 },
				    1.2:
					{'Configure Software Updates':
					     {'1.2.1': {'Ensure GPG keys are configured': result_dict[
						 'Ensure GPG keys are configured']},
					      '1.2.2': {'Ensure gpgcheck is globally activated': result_dict[
						  'Ensure gpgcheck is globally activated']},
					      '1.2.3': {'Ensure package manager repositories are configured': result_dict[
						  'Ensure package manager repositories are configured']}
					      }
					 },
				    1.3:
					{'Configure sudo':
					     {'1.3.1': {'Ensure sudo is installed': result_dict['Ensure sudo is installed']},
					      '1.3.2': {
						  'Ensure sudo commands use pty': result_dict['Ensure sudo commands use pty']},
					      '1.3.3': {
						  'Ensure sudo log file exists': result_dict['Ensure sudo log file exists']}
					      }
					 },
				    1.4:
					{'FileSystem Integrity Checking':
					     {'1.4.1': {'Ensure AIDE is installed': result_dict['Ensure AIDE is installed']},
					      '1.4.2': {'Ensure filesystem integrity is regularly checked': result_dict[
						  'Ensure filesystem integrity is regularly checked']}
					      }
					 },
				    1.5:
					{'Secure Boot Settings':
					     {'1.5.1': {'Ensure permissions on bootloader config are configured': result_dict[
						 'Ensure permissions on bootloader config are configured']},
					      '1.5.2': {'Ensure bootloader password is set': result_dict[
						  'Ensure bootloader password is set']},
					      '1.5.3': {'Ensure authentication required for single user mode': result_dict[
						  'Ensure authentication required for single user mode']}
					      }
					 },
				    1.6:
					{'Additional Process Hardening':
					     {'1.6.1': {'Ensure core dumps are restricted': result_dict[
						 'Ensure core dumps are restricted']},
					      '1.6.2': {
						  'Ensure address space layout randomization (ASLR) is enabled': result_dict[
						      'Ensure address space layout randomization (ASLR) is enabled']}
					      }
					 },
				    1.7:
					{'Mandatory Access Control':
					     {'1.7.1':
						  {'Configure SELinux':
						       {'1.7.1.1': {'Ensure SELinux is installed': result_dict[
							   'Ensure SELinux is installed']},
							'1.7.1.2': {
							    'Ensure SELinux is not disabled in bootloader configuration':
								result_dict[
								    'Ensure SELinux is not disabled in bootloader configuration']},
							'1.7.1.3': {'Ensure SELinux policy is configured': result_dict[
							    'Ensure SELinux policy is configured']},
							'1.7.1.4': {'Ensure the SELinux state is enforcing': result_dict[
							    'Ensure the SELinux state is enforcing']},
							'1.7.1.5': {'Ensure no unconfined services exist': result_dict[
							    'Ensure no unconfined services exist']},
							'1.7.1.6': {'Ensure SETroubleshoot is not installed': result_dict[
							    'Ensure SETroubleshoot is not installed']},
							'1.7.1.7': {'Ensure the MCS Translation Service (mcstrans) is not installed': result_dict[
							    'Ensure the MCS Translation Service (mcstrans) is not installed']}
							}
						   }
					      }},
				    1.8:
					{'Warning Banners':
					     {"1.8.1":
						  {"Command Line Warning Banners":
						       {'1.8.1.1': {
							   'Ensure message of the day is configured properly': result_dict[
							       'Ensure message of the day is configured properly']},
							'1.8.1.2': {'Ensure local login warning banner is configured properly':
									result_dict[
									    'Ensure local login warning banner is configured properly']},
							'1.8.1.3': {'Ensure remote login warning banner is configured properly':
									result_dict[
									    'Ensure remote login warning banner is configured properly']},
							'1.8.1.4': {
							    'Ensure permissions on /etc/motd are configured': result_dict[
								'Ensure permissions on /etc/motd are configured']},
							'1.8.1.5': {
							    'Ensure permissions on /etc/issue are configured': result_dict[
								'Ensure permissions on /etc/issue are configured']},
							'1.8.1.6': {
							    'Ensure permissions on /etc/issue.net are configured': result_dict[
								'Ensure permissions on /etc/issue.net are configured']}
							}
						   },
					      "1.8.2":
						  {"Ensure GDM login banner is configured": result_dict[
						      "Ensure GDM login banner is configured"]}
					      }
					 },
				    1.9: {"Ensure updates, patches, and additional security software are installed": result_dict[
					"Ensure updates, patches, and additional security software are installed"]},
				    1.10: {'Ensure system-wide crypto policy is not legacy': result_dict[
					'Ensure system-wide crypto policy is not legacy']},
				    1.11: {'Ensure system-wide crypto policy is FUTURE or FIPS': result_dict[
					'Ensure system-wide crypto policy is FUTURE or FIPS']}
				    }
			       },
			   2:
			       {'Services':
				    {2.1:
					 {'inetd Services':
					      {'2.1.1':
						   {'Ensure xinetd is not installed': result_dict[
						       'Ensure xinetd is not installed']}}},
				     2.2:
					 {'Special Purpose Services':
					      {'2.2.1':
						   {"Time Synchronization":
							{'2.2.1.1':
							     {'Ensure time synchronization is in use': result_dict[
								 'Ensure time synchronization is in use']},
							 '2.2.1.2': {'Ensure chrony is configured': result_dict[
							     'Ensure chrony is configured']}
							 }
						    },
					       '2.2.2': {'Ensure X Window System is not installed': result_dict[
						   'Ensure X Window System is not installed']},
					       '2.2.3': {'Ensure rsync service is not enabled': result_dict[
						   'Ensure rsync service is not enabled']},
					       '2.2.4': {'Ensure Avahi Server is not enabled': result_dict[
						   'Ensure Avahi Server is not enabled']},
					       '2.2.5': {'Ensure SNMP Server is not enabled': result_dict[
						   'Ensure SNMP Server is not enabled']},
					       '2.2.6': {'Ensure HTTP Proxy Server is not enabled': result_dict[
						   'Ensure HTTP Proxy Server is not enabled']},
					       '2.2.7': {
						   'Ensure Samba is not enabled': result_dict['Ensure Samba is not enabled']},
					       '2.2.8': {'Ensure IMAP and POP3 server is not enabled':
                                         result_dict['Ensure IMAP and POP3 server is not enabled']},
					       '2.2.9': {'Ensure HTTP server is not enabled':
                                         result_dict['Ensure HTTP server is not enabled']},
					       '2.2.10': {'Ensure FTP Server is not enabled':
                                          result_dict['Ensure FTP Server is not enabled']},
					       '2.2.11': {'Ensure DNS Server is not enabled':
                                          result_dict['Ensure DNS Server is not enabled']},
					       '2.2.12': {'Ensure NFS is not enabled':
                                          result_dict['Ensure NFS is not enabled']},
					       '2.2.13': {'Ensure RPC is not enabled':
                                          result_dict['Ensure RPC is not enabled']},
					       '2.2.14': {'Ensure LDAP server is not enabled':
                                          result_dict['Ensure LDAP server is not enabled']},
					       '2.2.15': {'Ensure DHCP Server is not enabled':
                                          result_dict['Ensure DHCP Server is not enabled']},
					       '2.2.16': {'Ensure CUPS is not enabled':
                                          result_dict['Ensure CUPS is not enabled']},
					       '2.2.17': {'Ensure NIS Server is not enabled':
                                          result_dict['Ensure NIS Server is not enabled']},
					       '2.2.18': {'Ensure mail transfer agent is configured for local-only mode':
                                          result_dict['Ensure mail transfer agent is configured for local-only mode']}
					       }},
				     2.3:
					 {'Service Clients':
					      {'2.3.1': {'Ensure NIS Client is not installed': result_dict[
						  'Ensure NIS Client is not installed']},
					       '2.3.2': {'Ensure telnet client is not installed': result_dict[
						   'Ensure telnet client is not installed']},
					       '2.3.3': {'Ensure LDAP client is not installed': result_dict[
						   'Ensure LDAP client is not installed']}
					       }
					  }
				     }
				},
			   3:
			       {'Network Configuration':
				    {3.1:
					 {'Network Parameters (Host Only)':
					      {'3.1.1': {'Ensure IP forwarding is disabled': result_dict[
						  'Ensure IP forwarding is disabled']},
					       '3.1.2': {'Ensure packet redirect sending is disabled': result_dict[
						   'Ensure packet redirect sending is disabled']}
					       }
					  },
				     3.2:
					 {"Network Parameters (Host and Router)":
					      {'3.2.1': {'Ensure source routed packets are not accepted': result_dict[
						  'Ensure source routed packets are not accepted']},
					       '3.2.2': {'Ensure ICMP redirects are not accepted': result_dict[
						   'Ensure ICMP redirects are not accepted']},
					       '3.2.3': {'Ensure secure ICMP redirects are not accepted': result_dict[
						   'Ensure secure ICMP redirects are not accepted']},
					       '3.2.4': {'Ensure suspicious packets are logged': result_dict[
						   'Ensure suspicious packets are logged']},
					       '3.2.5': {'Ensure broadcast ICMP requests are ignored': result_dict[
						   'Ensure broadcast ICMP requests are ignored']},
					       '3.2.6': {'Ensure bogus ICMP responses are ignored': result_dict[
						   'Ensure bogus ICMP responses are ignored']},
					       '3.2.7': {'Ensure Reverse Path Filtering is enabled': result_dict[
						   'Ensure Reverse Path Filtering is enabled']},
					       '3.2.8': {'Ensure TCP SYN Cookies is enabled': result_dict[
						   'Ensure TCP SYN Cookies is enabled']},
					       '3.2.9': {'Ensure IPv6 router advertisements are not accepted': result_dict[
						   'Ensure IPv6 router advertisements are not accepted']}
					       }
					  },
				     3.3:
					 {"Uncommon Network Protocols":
					      {'3.3.1': {'Ensure DCCP is disabled': result_dict['Ensure DCCP is disabled']},
					       '3.3.2': {'Ensure SCTP is disabled': result_dict['Ensure SCTP is disabled']},
					       '3.3.3': {'Ensure RDS is disabled': result_dict['Ensure RDS is disabled']},
					       '3.3.4': {'Ensure TIPC is disabled': result_dict['Ensure TIPC is disabled']}
					       }},
				     3.4:
					 {"Firewall Configuration":
					      {"3.4.1":
						   {"Ensure Firewall software is installed":
							{'3.4.1.1': {'Ensure a Firewall package is installed': result_dict[
							    'Ensure a Firewall package is installed']}}
						    },
					       "3.4.2":
						   {"Configure firewalld":
							{'3.4.2.1': {
							    'Ensure firewalld service is enabled and running': result_dict[
								'Ensure firewalld service is enabled and running']},
							 '3.4.2.2': {'Ensure iptables service is not enabled with firewalld':
									 result_dict[
									     'Ensure iptables service is not enabled with firewalld']},
							 '3.4.2.3': {
							     'Ensure nftables is not enabled with firewalld': result_dict[
								 'Ensure nftables is not enabled with firewalld']},
							 '3.4.2.4': {'Ensure firewalld default zone is set': result_dict[
							     'Ensure firewalld default zone is set']},
							 '3.4.2.5': {
							     'Ensure network interfaces are assigned to appropriate zone':
								 result_dict[
								     'Ensure network interfaces are assigned to appropriate zone']},
							 '3.4.2.6': {'Ensure firewalld drops unnecessary services and ports':
									 result_dict[
									     'Ensure firewalld drops unnecessary services and ports']}}},
					       "3.4.3":
						   {"Configure nftables":
							{'3.4.3.1': {'Ensure iptables are flushed with nftables': result_dict[
							    'Ensure iptables are flushed with nftables']},
							 '3.4.3.2': {'Ensure an nftables table exists': result_dict[
							     'Ensure an nftables table exists']},
							 '3.4.3.3': {'Ensure nftables base chains exist': result_dict[
							     'Ensure nftables base chains exist']},
							 '3.4.3.4': {
							     'Ensure nftables loopback traffic is configured': result_dict[
								 'Ensure nftables loopback traffic is configured']},
							 '3.4.3.6': {
							     'Ensure nftables default deny firewall policy': result_dict[
								 'Ensure nftables default deny firewall policy']},
							 '3.4.3.7': {'Ensure nftables service is enabled': result_dict[
							     'Ensure nftables service is enabled']},
							 '3.4.3.8': {'Ensure nftables rules are permanent': result_dict[
							     'Ensure nftables rules are permanent']}
							 }},
					       "3.4.4":
						   {"Configure iptables":
							{'3.4.4.1.1': {
							    'Ensure iptables default deny firewall policy': result_dict[
								'Ensure iptables default deny firewall policy']},
							 '3.4.4.1.2': {
							     'Ensure iptables loopback traffic is configured': result_dict[
								 'Ensure iptables loopback traffic is configured']},
							 '3.4.4.1.4': {
							     'Ensure iptables firewall rules exist for all open ports':
								 result_dict[
								     'Ensure iptables firewall rules exist for all open ports']},
							 '3.4.4.1.5': {'Ensure iptables is enabled and active': result_dict[
							     'Ensure iptables is enabled and active']},
							 '3.4.4.1.6': {'Ensure iptables is enabled and active': result_dict[
							     'Ensure iptables is enabled and active']},
							 '3.4.4.2.1': {
							     'Ensure ip6tables default deny firewall policy': result_dict[
								 'Ensure ip6tables default deny firewall policy']},
							 '3.4.4.2.2': {
							     'Ensure ip6tables loopback traffic is configured': result_dict[
								 'Ensure ip6tables loopback traffic is configured']},
							 '3.4.4.2.4': {
							     'Ensure ip6tables firewall rules exist for all open ports':
								 result_dict[
								     'Ensure ip6tables firewall rules exist for all open ports']},
							 '3.4.4.2.5': {'Ensure ip6tables is enabled and active': result_dict[
							     'Ensure ip6tables is enabled and active']}
							 }
						    }
					       },
					  3.5:
					      {"Ensure wireless interfaces are disabled": result_dict[
						  "Ensure wireless interfaces are disabled"]},
					  3.6:
					      {"Disable IPv6": result_dict["Disable IPv6"]}
					  }
				     }
				},
			   4:
			       {'Logging and Auditing':
				    {4.1:
					 {"Configure System Accounting":
					      {"4.1.1":
						   {'Ensure auditing is enabled':
							{'4.1.1.1': {'Ensure auditd is installed': result_dict[
							    'Ensure auditd is installed']},
							 '4.1.1.2': {'Ensure auditd service is enabled': result_dict[
							     'Ensure auditd service is enabled']},
							 '4.1.1.3': {
							     'Ensure auditing for processes that start prior to auditd is enabled':
								 result_dict[
								     "Ensure auditing for processes that start prior to auditd is enabled"]},
							 '4.1.1.4': {'Ensure audit_backlog_limit is sufficient': result_dict[
							     'Ensure audit_backlog_limit is sufficient']}}
						    },
					       "4.1.2":
						   {"Configure Data Retention":
							{'4.1.2.1': {'Ensure audit log storage size is configured': result_dict[
							    'Ensure audit log storage size is configured']},
							 '4.1.2.2': {
							     'Ensure audit logs are not automatically deleted': result_dict[
								 'Ensure audit logs are not automatically deleted']},
							 '4.1.2.3': {
							     'Ensure system is disabled when audit logs are full': result_dict[
								 'Ensure system is disabled when audit logs are full']}}
						    },
					       '4.1.3': {'Ensure changes to system administration scope (sudoers) is collected': result_dict[
						   'Ensure changes to system administration scope (sudoers) is collected']},
					       '4.1.4': {'Ensure login and logout events are collected': result_dict[
						   'Ensure login and logout events are collected']},
					       '4.1.5': {'Ensure session initiation information is collected': result_dict[
						   'Ensure session initiation information is collected']},
					       '4.1.6': {'Ensure events that modify date and time information are collected':
							     result_dict[
								 "Ensure events that modify date and time information are collected"]},
					       '4.1.7': {
						   "Ensure events that modify the system's Mandatory Access Controls are collected":
						       result_dict[
							   "Ensure events that modify the system's Mandatory Access Controls are collected"]},
					       '4.1.8': {
						   "Ensure events that modify the system's network environment are collected":
						       result_dict[
							   "Ensure events that modify the system's network environment are collected"]},
					       '4.1.9': {
						   "Ensure discretionary access control permission modification events are collected":
						       result_dict[
							   "Ensure discretionary access control permission modification events are collected"]},
					       '4.1.10': {"Ensure unsuccessful unauthorized file access attempts are collected":
							      result_dict[
								  "Ensure unsuccessful unauthorized file access attempts are collected"]},
					       '4.1.11': {"Ensure events that modify user/group information are collected":
							      result_dict[
								  "Ensure events that modify user/group information are collected"]},
					       '4.1.12': {"Ensure successful file system mounts are collected": result_dict[
						   "Ensure successful file system mounts are collected"]},
					       '4.1.13': {"Ensure use of privileged commands is collected": result_dict[
						   "Ensure use of privileged commands is collected"]},
					       '4.1.14': {"Ensure file deletion events by users are collected": result_dict[
						   "Ensure file deletion events by users are collected"]},
					       '4.1.15': {
						   "Ensure kernel module loading and unloading is collected": result_dict[
						       "Ensure kernel module loading and unloading is collected"]},
					       '4.1.16': {
						   "Ensure system administrator actions (sudolog) are collected": result_dict[
						       "Ensure system administrator actions (sudolog) are collected"]},
					       '4.1.17': {"Ensure the audit configuration is immutable": result_dict[
						   "Ensure the audit configuration is immutable"]}
					       }
					  },
				     4.2:
					 {'Configure Logging':
					      {"4.2.1":
						   {"Configure rsyslog":
							{'4.2.1.1': {'Ensure rsyslog is installed': result_dict[
							    'Ensure rsyslog is installed']},
							 '4.2.1.2': {'Ensure rsyslog Service is enabled': result_dict[
							     'Ensure rsyslog Service is enabled']},
							 '4.2.1.3': {
							     'Ensure rsyslog default file permissions configured': result_dict[
								 'Ensure rsyslog default file permissions configured']},
							 '4.2.1.4': {'Ensure logging is configured': result_dict[
							     'Ensure logging is configured']},
							 '4.2.1.5': {
							     'Ensure rsyslog is configured to send logs to a remote log host':
								 result_dict[
								     'Ensure rsyslog is configured to send logs to a remote log host']}}
						    },
					       "4.2.2":
						   {"Configure journald":
							{'4.2.2.1': {'Ensure journald is configured to send logs to rsyslog':
									 result_dict[
									     'Ensure journald is configured to send logs to rsyslog']},
							 '4.2.2.2': {
							     'Ensure journald is configured to compress large log files':
								 result_dict[
								     'Ensure journald is configured to compress large log files']}}
						    },
					       '4.2.3':
						   {'Ensure permissions on all logfiles are configured':
							result_dict['Ensure permissions on all logfiles are configured']}
					       }
					  },
				     4.3: {"Ensure logrotate is configured": result_dict["Ensure logrotate is configured"]}
				     }
				},
			   5:
			       {'Access, Authentication and Authorization':
				    {5.1: {"Configure cron":
					       {'5.1.1': {'Ensure cron daemon is enabled': result_dict[
						   'Ensure cron daemon is enabled']}, '5.1.2': {
						   'Ensure permissions on /etc/crontab are configured': result_dict[
						       'Ensure permissions on /etc/crontab are configured']},
						'5.1.3': {'Ensure permissions on /etc/cron.hourly are configured': result_dict[
						    'Ensure permissions on /etc/cron.hourly are configured']},
						'5.1.4': {'Ensure permissions on /etc/cron.daily are configured': result_dict[
						    'Ensure permissions on /etc/cron.daily are configured']},
						'5.1.5': {'Ensure permissions on /etc/cron.weekly are configured': result_dict[
						    'Ensure permissions on /etc/cron.weekly are configured']},
						'5.1.6': {'Ensure permissions on /etc/cron.monthly are configured': result_dict[
						    'Ensure permissions on /etc/cron.monthly are configured']},
						'5.1.7': {'Ensure permissions on /etc/cron.d are configured': result_dict[
						    'Ensure permissions on /etc/cron.d are configured']},
						'5.1.8': {'Ensure at/cron is restricted to authorized users': result_dict[
						    'Ensure at/cron is restricted to authorized users']},
						}},
				     5.2: {"SSH Server Configuration":
					       {'5.2.1': {
						   'Ensure permissions on /etc/ssh/sshd_config are configured': result_dict[
						       'Ensure permissions on /etc/ssh/sshd_config are configured']},
						'5.2.2': {'Ensure SSH access is limited': result_dict[
						    'Ensure SSH access is limited']},
						'5.2.4': {'Ensure permissions on SSH public host key files are configured':
							      result_dict[
								  'Ensure permissions on SSH public host key files are configured']},
						'5.2.5': {'Ensure SSH LogLevel is appropriate': result_dict[
						    'Ensure SSH LogLevel is appropriate']},
						'5.2.6': {'Ensure SSH X11 forwarding is disabled': result_dict[
						    'Ensure SSH X11 forwarding is disabled']},
						'5.2.7': {'Ensure SSH MaxAuthTries is set to 4 or less': result_dict[
						    'Ensure SSH MaxAuthTries is set to 4 or less']},
						'5.2.8': {'Ensure SSH IgnoreRhosts is enabled': result_dict[
						    'Ensure SSH IgnoreRhosts is enabled']},
						'5.2.9': {'Ensure SSH HostbasedAuthentication is disabled': result_dict[
						    'Ensure SSH HostbasedAuthentication is disabled']},
						'5.2.10': {'Ensure SSH root login is disabled': result_dict[
						    'Ensure SSH root login is disabled']},
						'5.2.11': {'Ensure SSH PermitEmptyPasswords is disabled': result_dict[
						    'Ensure SSH PermitEmptyPasswords is disabled']},
						'5.2.12': {'Ensure SSH PermitUserEnvironment is disabled': result_dict[
						    'Ensure SSH PermitUserEnvironment is disabled']},
						'5.2.13': {'Ensure SSH Idle Timeout Interval is configured': result_dict[
						    'Ensure SSH Idle Timeout Interval is configured']},
						'5.2.14': {
						    'Ensure SSH LoginGraceTime is set to one minute or less': result_dict[
							'Ensure SSH LoginGraceTime is set to one minute or less']},
						'5.2.15': {'Ensure SSH warning banner is configured': result_dict[
						    'Ensure SSH warning banner is configured']},
						'5.2.16': {
						    'Ensure SSH PAM is enabled': result_dict['Ensure SSH PAM is enabled']},
						'5.2.17': {'Ensure SSH AllowTcpForwarding is disabled': result_dict[
						    'Ensure SSH AllowTcpForwarding is disabled']},
						'5.2.18': {'Ensure SSH MaxStartups is configured': result_dict[
						    'Ensure SSH MaxStartups is configured']},
						'5.2.19': {'Ensure SSH MaxSessions is set to 4 or less': result_dict[
						    'Ensure SSH MaxSessions is set to 4 or less']},
						'5.2.20': {'Ensure system-wide crypto policy is not over-ridden': result_dict[
						    'Ensure system-wide crypto policy is not over-ridden']}}},
				     5.3: {"Configure authselect":
					       {'5.3.1': {'Create custom authselect profile': result_dict[
						   'Create custom authselect profile']},
						'5.3.2': {
						    'Select authselect profile': result_dict['Select authselect profile']},
						'5.3.3': {'Ensure authselect includes with-faillock': result_dict[
						    'Ensure authselect includes with-faillock']}}},
				     5.4: {"Configure PAM":
					       {'5.4.1': {'Ensure password creation requirements are configured': result_dict[
						   'Ensure password creation requirements are configured']},
						'5.4.2': {
						    'Ensure lockout for failed password attempts is configured': result_dict[
							'Ensure lockout for failed password attempts is configured']},
						'5.4.3': {'Ensure password reuse is limited': result_dict[
						    'Ensure password reuse is limited']},
						'5.4.4': {'Ensure password hashing algorithm is SHA-512': result_dict[
						    'Ensure password hashing algorithm is SHA-512']}}},
				     5.5: {"User Accounts and Entertainment":
					       {'5.5.1':
						    {'Set Shadow Password Suite Parameters':
							 {'5.5.1.1': {
							     'Ensure password expiration is 365 days or less': result_dict[
								 'Ensure password expiration is 365 days or less']},
							  '5.5.1.2': {
							      'Ensure minimum days between password changes is 7 or more':
								  result_dict[
								      'Ensure minimum days between password changes is 7 or more']},
							  '5.5.1.3': {'Ensure password expiration warning days is 7 or more':
									  result_dict[
									      'Ensure password expiration warning days is 7 or more']},
							  '5.5.1.4': {
							      'Ensure inactive password lock is 30 days or less': result_dict[
								  'Ensure inactive password lock is 30 days or less']},
							  '5.5.1.5': {
							      'Ensure all users last password change date is in the past':
								  result_dict[
								      'Ensure all users last password change date is in the past']}}
						     },
						'5.5.2': {'Ensure system accounts are secured': result_dict[
						    'Ensure system accounts are secured']},
						'5.5.3': {
						    'Ensure default user shell timeout is 900 seconds or less': result_dict[
							'Ensure default user shell timeout is 900 seconds or less']},
						'5.5.4': {'Ensure default group for the root account is GID 0': result_dict[
						    'Ensure default group for the root account is GID 0']}
						#'5.5.5': {'Ensure default user umask is 027 or more restrictive': result_dict[
						#    'Ensure default user umask is 027 or more restrictive']}
						}
					   },
				     5.6: {'Ensure root login is restricted to system console': result_dict[
					 'Ensure root login is restricted to system console']},
				     5.7: {'Ensure access to the su command is restricted': result_dict[
					 'Ensure access to the su command is restricted']}
				     }
				},
			   6:
			       {"System Maintenance":
				    {6.1: {"System File Permissions":
					       {'6.1.1': {'Audit system file permissions': result_dict[
						   'Audit system file permissions']},
						'6.1.2': {'Ensure permissions on /etc/passwd are configured': result_dict[
						    'Ensure permissions on /etc/passwd are configured']},
						'6.1.3': {'Ensure permissions on /etc/passwd- are configured': result_dict[
						    'Ensure permissions on /etc/passwd- are configured']},
						'6.1.4': {'Ensure permissions on /etc/shadow are configured': result_dict[
						    'Ensure permissions on /etc/shadow are configured']},
						'6.1.5': {'Ensure permissions on /etc/shadow- are configured': result_dict[
						    'Ensure permissions on /etc/shadow- are configured']},
						'6.1.6': {'Ensure permissions on /etc/gshadow are configured': result_dict[
						    'Ensure permissions on /etc/gshadow are configured']},
						'6.1.7': {'Ensure permissions on /etc/gshadow- are configured': result_dict[
						    'Ensure permissions on /etc/gshadow- are configured']},
						'6.1.8': {'Ensure permissions on /etc/group are configured': result_dict[
						    'Ensure permissions on /etc/group are configured']},
						'6.1.9': {'Ensure permissions on /etc/group- are configured': result_dict[
						    'Ensure permissions on /etc/group- are configured']},
						'6.1.10': {'Ensure no world writable files exist': result_dict[
						    'Ensure no world writable files exist']},
						'6.1.11': {'Ensure no unowned files or directories exist': result_dict[
						    'Ensure no unowned files or directories exist']},
						'6.1.12': {'Ensure no ungrouped files or directories exist': result_dict[
						    'Ensure no ungrouped files or directories exist']},
						'6.1.13': {'Audit SUID executables': result_dict['Audit SUID executables']},
						'6.1.14': {'Audit SGID executables': result_dict['Audit SGID executables']}}
					   },
				     6.2: {"User and Group Settings":
					       {'6.2.1': {'Ensure password fields are not empty': result_dict[
						   'Ensure password fields are not empty']},
                            '6.2.2': {'Ensure no legacy "+" entries exist in /etc/passwd': result_dict[
                                'Ensure no legacy "+" entries exist in /etc/passwd']},
                            '6.2.3': {'Ensure root PATH Integrity':
                                          result_dict['Ensure root PATH Integrity']},
						    '6.2.4': {'Ensure no legacy "+" entries exist in /etc/shadow': result_dict[
						        'Ensure no legacy "+" entries exist in /etc/shadow']},
						    '6.2.5': {'Ensure no legacy "+" entries exist in /etc/group': result_dict[
						        'Ensure no legacy "+" entries exist in /etc/group']},
						    '6.2.6': {'Ensure root is the only UID 0 account': result_dict[
						        'Ensure root is the only UID 0 account']},
						    '6.2.8': {'Ensure users own their home directories': result_dict[
						        'Ensure users own their home directories']},
						    "6.2.9": {
						        "Ensure users' dot files are not group or world writable": result_dict[
							    "Ensure users' dot files are not group or world writable"]},
						    '6.2.10': {'Ensure no users have .forward files': result_dict[
						        'Ensure no users have .forward files']},
						    '6.2.11': {'Ensure no users have .netrc files': result_dict[
						        'Ensure no users have .netrc files']},
						    "6.2.12": {"Ensure users' .netrc Files are not group or world accessible":
                                           result_dict["Ensure users' .netrc Files are not group or world accessible"]},
						    '6.2.13': {'Ensure no users have .rhosts files':
                                           result_dict['Ensure no users have .rhosts files']},
						    '6.2.14': {'Ensure all groups in /etc/passwd exist in /etc/group':
                                           result_dict['Ensure all groups in /etc/passwd exist in /etc/group']},
						    '6.2.15': {'Ensure no duplicate UIDs exist': result_dict[
						        'Ensure no duplicate UIDs exist']},
						    '6.2.16': {'Ensure no duplicate GIDs exist': result_dict[
						        'Ensure no duplicate GIDs exist']},
						    '6.2.17': {'Ensure no duplicate user names exist': result_dict[
						        'Ensure no duplicate user names exist']},
						    '6.2.18': {'Ensure no duplicate group names exist': result_dict[
						        'Ensure no duplicate group names exist']},
						    '6.2.19': {'Ensure shadow group is empty': result_dict[
						        'Ensure shadow group is empty']},
						    "6.2.20": {"Ensure all users' home directories exist": result_dict[
						        "Ensure all users' home directories exist"]}}
					   }
				     }
				}
	    }
    print(parent_dict)
    fileobj = open("benchmark.json", "w")
    json.dump(parent_dict, fileobj)
    fileobj.close()
