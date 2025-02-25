require 'spec_helper'

RSpec.describe Msf::Post::Linux::System do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Post::Linux::System)
    mod
  end

  describe '#get_sysinfo' do
    context 'when the system is Debian' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('debian_version')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 4.15.0-20-generic (buildd@lgw01-amd64)')
        allow(subject).to receive(:read_file).with('/etc/issue').and_return('Debian GNU/Linux 9 \\n \\l')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('debian')
        expect(sysinfo[:version]).to eq('Debian GNU/Linux 9')
        expect(sysinfo[:kernel]).to eq('Linux version 4.15.0-20-generic (buildd@lgw01-amd64)')
      end
    end

    context 'when the system is Ubuntu' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('debian_version')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 4.15.0-20-generic (buildd@lgw01-amd64) Ubuntu')
        allow(subject).to receive(:read_file).with('/etc/issue').and_return('Ubuntu 18.04.1 LTS \\n \\l')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('ubuntu')
        expect(sysinfo[:version]).to eq('Ubuntu 18.04.1 LTS')
        expect(sysinfo[:kernel]).to eq('Linux version 4.15.0-20-generic (buildd@lgw01-amd64) Ubuntu')
      end
    end

    context 'when the system is Amazon or CentOS' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('system-release')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 4.14.88-88.76.amzn2.x86_64 (mockbuild@gobi-build-60008) (gcc version 7.3.1 20180303 (Red Hat 7.3.1-5) (GCC))')
        allow(subject).to receive(:read_file).with('/etc/system-release').and_return('Amazon Linux 2')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('amazon')
        expect(sysinfo[:version]).to eq('Amazon Linux 2')
        expect(sysinfo[:kernel]).to eq('Linux version 4.14.88-88.76.amzn2.x86_64 (mockbuild@gobi-build-60008) (gcc version 7.3.1 20180303 (Red Hat 7.3.1-5) (GCC))')
      end
    end

    context 'when the system is Alpine' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('alpine-release')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 4.19.0-0-virt (buildozer@build-3-10-x86_64)')
        allow(subject).to receive(:read_file).with('/etc/alpine-release').and_return('3.10.2')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('alpine')
        expect(sysinfo[:version]).to eq('3.10.2')
        expect(sysinfo[:kernel]).to eq('Linux version 4.19.0-0-virt (buildozer@build-3-10-x86_64)')
      end
    end

    context 'when the system is Fedora' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('fedora-release')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 5.3.7-301.fc31.x86_64 (mockbuild@bkernel01.phx2.fedoraproject.org)')
        allow(subject).to receive(:read_file).with('/etc/fedora-release').and_return('Fedora release 31 (Thirty One)')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('fedora')
        expect(sysinfo[:version]).to eq('Fedora release 31 (Thirty One)')
        expect(sysinfo[:kernel]).to eq('Linux version 5.3.7-301.fc31.x86_64 (mockbuild@bkernel01.phx2.fedoraproject.org)')
      end
    end

    context 'when the system is Oracle Linux' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('enterprise-release')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 4.14.35-1818.3.3.el7uek.x86_64 (mockbuild@x86-ol7-builder-02)')
        allow(subject).to receive(:read_file).with('/etc/enterprise-release').and_return('Oracle Linux Server release 7.6')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('oracle')
        expect(sysinfo[:version]).to eq('Oracle Linux Server release 7.6')
        expect(sysinfo[:kernel]).to eq('Linux version 4.14.35-1818.3.3.el7uek.x86_64 (mockbuild@x86-ol7-builder-02)')
      end
    end

    context 'when the system is RedHat' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('redhat-release')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 3.10.0-957.21.3.el7.x86_64 (mockbuild@x86-01.bsys.centos.org)')
        allow(subject).to receive(:read_file).with('/etc/redhat-release').and_return('Red Hat Enterprise Linux Server release 7.6 (Maipo)')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('redhat')
        expect(sysinfo[:version]).to eq('Red Hat Enterprise Linux Server release 7.6 (Maipo)')
        expect(sysinfo[:kernel]).to eq('Linux version 3.10.0-957.21.3.el7.x86_64 (mockbuild@x86-01.bsys.centos.org)')
      end
    end

    context 'when the system is Arch' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('arch-release')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 5.3.7-arch1-1-ARCH (builduser@heftig-29959)')
        allow(subject).to receive(:read_file).with('/etc/arch-release').and_return('Arch Linux')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('arch')
        expect(sysinfo[:version]).to eq('Arch Linux')
        expect(sysinfo[:kernel]).to eq('Linux version 5.3.7-arch1-1-ARCH (builduser@heftig-29959)')
      end
    end

    context 'when the system is Slackware' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('slackware-version')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 4.4.14 (root@darkstar)')
        allow(subject).to receive(:read_file).with('/etc/slackware-version').and_return('Slackware 14.2')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('slackware')
        expect(sysinfo[:version]).to eq('Slackware 14.2')
        expect(sysinfo[:kernel]).to eq('Linux version 4.4.14 (root@darkstar)')
      end
    end

    context 'when the system is Mandrake' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('mandrake-release')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 2.6.12-12mdk (nplanel@no.mandriva.com)')
        allow(subject).to receive(:read_file).with('/etc/mandrake-release').and_return('Mandrake Linux release 10.2 (Limited Edition 2005)')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('mandrake')
        expect(sysinfo[:version]).to eq('Mandrake Linux release 10.2 (Limited Edition 2005)')
        expect(sysinfo[:kernel]).to eq('Linux version 2.6.12-12mdk (nplanel@no.mandriva.com)')
      end
    end

    context 'when the system is SuSE' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('SuSE-release')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 4.12.14-lp151.28.36-default (geeko@buildhost)')
        allow(subject).to receive(:read_file).with('/etc/SuSE-release').and_return('openSUSE Leap 15.1')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('suse')
        expect(sysinfo[:version]).to eq('openSUSE Leap 15.1')
        expect(sysinfo[:kernel]).to eq('Linux version 4.12.14-lp151.28.36-default (geeko@buildhost)')
      end
    end

    context 'when the system is OpenSUSE' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('SUSE-brand')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 4.12.14-lp151.28.36-default (geeko@buildhost)')
        allow(subject).to receive(:read_file).with('/etc/SUSE-brand').and_return('VERSION = 15.1')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('suse')
        expect(sysinfo[:version]).to eq('15.1')
        expect(sysinfo[:kernel]).to eq('Linux version 4.12.14-lp151.28.36-default (geeko@buildhost)')
      end
    end

    context 'when the system is Gentoo' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('gentoo-release')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 4.19.57-gentoo (root@localhost)')
        allow(subject).to receive(:read_file).with('/etc/gentoo-release').and_return('Gentoo Base System release 2.6')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('gentoo')
        expect(sysinfo[:version]).to eq('Gentoo Base System release 2.6')
        expect(sysinfo[:kernel]).to eq('Linux version 4.19.57-gentoo (root@localhost)')
      end
    end

    context 'when the system is Openwall' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('owl-release')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 2.6.32-431.el6.x86_64 (mockbuild@c6b8.bsys.dev.centos.org)')
        allow(subject).to receive(:read_file).with('/etc/owl-release').and_return('Openwall GNU/*/Linux 3.1 (2014-09-26)')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('openwall')
        expect(sysinfo[:version]).to eq('Openwall GNU/*/Linux 3.1 (2014-09-26)')
        expect(sysinfo[:kernel]).to eq('Linux version 2.6.32-431.el6.x86_64 (mockbuild@c6b8.bsys.dev.centos.org)')
      end
    end

    context 'when the system is Generic Linux' do
      it 'returns the correct system information' do
        allow(subject).to receive(:cmd_exec).with('ls /etc').and_return('issue')
        allow(subject).to receive(:cmd_exec).with('uname -a').and_return('Linux version 4.19.0-0-virt (buildozer@build-3-10-x86_64)')
        allow(subject).to receive(:read_file).with('/etc/issue').and_return('Generic Linux')
        allow(subject).to receive(:report_host)

        sysinfo = subject.get_sysinfo

        expect(sysinfo[:distro]).to eq('linux')
        expect(sysinfo[:version]).to eq('Generic Linux')
        expect(sysinfo[:kernel]).to eq('Linux version 4.19.0-0-virt (buildozer@build-3-10-x86_64)')
      end
    end
  end

  describe '#get_suid_files' do
    context 'when there are no permission denied errors' do
      it 'returns the list of SUID files' do
        suid_files = "/usr/bin/passwd\n/usr/bin/sudo\n"
        allow(subject).to receive(:cmd_exec).with('find / -perm -4000 -print -xdev').and_return(suid_files)

        result = subject.get_suid_files

        expect(result).to eq(['/usr/bin/passwd', '/usr/bin/sudo'])
      end
    end

    context 'when there are permission denied errors' do
      it 'filters out the permission denied errors' do
        suid_files = "/usr/bin/passwd\nfind: ‘/root’: Permission denied\n/usr/bin/sudo\n"
        allow(subject).to receive(:cmd_exec).with('find / -perm -4000 -print -xdev').and_return(suid_files)

        result = subject.get_suid_files

        expect(result).to eq(['/usr/bin/passwd', '/usr/bin/sudo'])
      end
    end

    context 'when an error occurs' do
      it 'raises an error' do
        allow(subject).to receive(:cmd_exec).with('find / -perm -4000 -print -xdev').and_raise(StandardError)

        expect { subject.get_suid_files }.to raise_error('Could not retrieve all SUID files')
      end
    end
  end

  describe '#get_path' do
    it 'returns the system path' do
      allow(subject).to receive(:cmd_exec).with('echo $PATH').and_return('/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
      expect(subject.get_path).to eq('/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
    end

    it 'raises an error if unable to determine path' do
      allow(subject).to receive(:cmd_exec).with('echo $PATH').and_raise(StandardError)
      expect { subject.get_path }.to raise_error('Unable to determine path')
    end
  end

  describe '#get_cpu_info' do
    it 'returns the CPU information' do
      cpuinfo = "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu MHz\t\t: 2400.000\nmodel name\t: Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz\n"
      allow(subject).to receive(:read_file).with('/proc/cpuinfo').and_return(cpuinfo)
      expect(subject.get_cpu_info).to eq({ speed_mhz: 2400, product: 'Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz', vendor: 'GenuineIntel', cores: 1 })
    end

    it 'raises an error if unable to get CPU information' do
      allow(subject).to receive(:read_file).with('/proc/cpuinfo').and_raise(StandardError)
      expect { subject.get_cpu_info }.to raise_error('Could not get CPU information')
    end
  end

  describe '#get_hostname' do
    it 'returns the hostname using uname' do
      allow(subject).to receive(:command_exists?).with('uname').and_return(true)
      allow(subject).to receive(:cmd_exec).with('uname -n').and_return('test-hostname')
      allow(subject).to receive(:report_host)
      expect(subject.get_hostname).to eq('test-hostname')
    end

    it 'returns the hostname using /proc/sys/kernel/hostname' do
      allow(subject).to receive(:command_exists?).with('uname').and_return(false)
      allow(subject).to receive(:read_file).with('/proc/sys/kernel/hostname').and_return('test-hostname')
      allow(subject).to receive(:report_host)
      expect(subject.get_hostname).to eq('test-hostname')
    end

    it 'raises an error if unable to retrieve hostname' do
      allow(subject).to receive(:cmd_exec).with('uname -n').and_raise(StandardError)
      expect { subject.get_hostname }.to raise_error('Unable to retrieve hostname')
    end
  end

  describe '#get_shell_name' do
    it 'returns the shell name using ps' do
      allow(subject).to receive(:command_exists?).with('ps').and_return(true)
      allow(subject).to receive(:cmd_exec).with('ps -p $$').and_return("PID TTY          TIME CMD\n  1 ?        00:00:00 bash")
      expect(subject.get_shell_name).to eq('bash')
    end

    it 'returns the shell name using echo $0' do
      allow(subject).to receive(:command_exists?).with('ps').and_return(false)
      allow(subject).to receive(:cmd_exec).with('echo $0').and_return('-bash')
      expect(subject.get_shell_name).to eq('bash')
    end

    it 'raises an error if unable to gather shell name' do
      allow(subject).to receive(:cmd_exec).with('ps -p $$').and_raise(StandardError)
      expect { subject.get_shell_name }.to raise_error('Unable to gather shell name')
    end
  end

  describe '#get_shell_pid' do
    it 'returns the shell pid' do
      allow(subject).to receive(:cmd_exec).with('echo $$').and_return('1234')
      expect(subject.get_shell_pid).to eq('1234')
    end
  end

  describe '#has_gcc?' do
    it 'returns true if gcc is installed' do
      allow(subject).to receive(:command_exists?).with('gcc').and_return(true)
      expect(subject.has_gcc?).to be true
    end

    it 'raises an error if unable to check for gcc' do
      allow(subject).to receive(:command_exists?).with('gcc').and_raise(StandardError)
      expect { subject.has_gcc? }.to raise_error('Unable to check for gcc')
    end
  end

  describe '#has_clang?' do
    it 'returns true if clang is installed' do
      allow(subject).to receive(:command_exists?).with('clang').and_return(true)
      expect(subject.has_clang?).to be true
    end

    it 'raises an error if unable to check for clang' do
      allow(subject).to receive(:command_exists?).with('clang').and_raise(StandardError)
      expect { subject.has_clang? }.to raise_error('Unable to check for clang')
    end
  end

  describe '#noexec?' do
    it 'returns true if the file path is mounted on a noexec mount point' do
      mount_content = "/dev/sda1 / ext4 rw,noexec 0 0\n"
      allow(subject).to receive(:read_file).with('/proc/mounts').and_return(mount_content)
      allow(subject).to receive(:get_mount_path).with('/path/to/file').and_return('/')
      expect(subject.noexec?('/path/to/file')).to be true
    end

    it 'raises an error if unable to check for noexec volume' do
      allow(subject).to receive(:read_file).with('/proc/mounts').and_raise(StandardError)
      expect { subject.noexec?('/path/to/file') }.to raise_error('Unable to check for noexec volume')
    end
  end

  describe '#nosuid?' do
    it 'returns true if the file path is mounted on a nosuid mount point' do
      mount_content = "/dev/sda1 / ext4 rw,nosuid 0 0\n"
      allow(subject).to receive(:read_file).with('/proc/mounts').and_return(mount_content)
      allow(subject).to receive(:get_mount_path).with('/path/to/file').and_return('/')
      expect(subject.nosuid?('/path/to/file')).to be true
    end

    it 'raises an error if unable to check for nosuid volume' do
      allow(subject).to receive(:read_file).with('/proc/mounts').and_raise(StandardError)
      expect { subject.nosuid?('/path/to/file') }.to raise_error('Unable to check for nosuid volume')
    end
  end

  describe '#protected_hardlinks?' do
    it 'returns true if protected hardlinks are enabled' do
      allow(subject).to receive(:read_file).with('/proc/sys/fs/protected_hardlinks').and_return('1')
      expect(subject.protected_hardlinks?).to be true
    end

    it 'raises an error if unable to determine protected_hardlinks status' do
      allow(subject).to receive(:read_file).with('/proc/sys/fs/protected_hardlinks').and_raise(StandardError)
      expect { subject.protected_hardlinks? }.to raise_error('Could not determine protected_hardlinks status')
    end
  end

  describe '#protected_symlinks?' do
    it 'returns true if protected symlinks are enabled' do
      allow(subject).to receive(:read_file).with('/proc/sys/fs/protected_symlinks').and_return('1')
      expect(subject.protected_symlinks?).to be true
    end

    it 'raises an error if unable to determine protected_symlinks status' do
      allow(subject).to receive(:read_file).with('/proc/sys/fs/protected_symlinks').and_raise(StandardError)
      expect { subject.protected_symlinks? }.to raise_error('Could not determine protected_symlinks status')
    end
  end

  describe '#glibc_version' do
    it 'returns the glibc version' do
      allow(subject).to receive(:command_exists?).with('ldd').and_return(true)
      allow(subject).to receive(:cmd_exec).with('ldd --version').and_return('ldd (GNU libc) 2.27')
      expect(subject.glibc_version).to eq('2.27')
    end

    it 'raises an error if glibc is not installed' do
      allow(subject).to receive(:command_exists?).with('ldd').and_return(false)
      expect { subject.glibc_version }.to raise_error('glibc is not installed')
    end

    it 'raises an error if unable to determine glibc version' do
      allow(subject).to receive(:command_exists?).with('ldd').and_return(true)
      allow(subject).to receive(:cmd_exec).with('ldd --version').and_raise(StandardError)
      expect { subject.glibc_version }.to raise_error('Could not determine glibc version')
    end
  end

  describe '#get_mount_path' do
    it 'returns the mount path of the file' do
      allow(subject).to receive(:cmd_exec).with('df "/path/to/file" | tail -1').and_return('/dev/sda1 101141520 52963696 42993928 56% /')
      expect(subject.get_mount_path('/path/to/file')).to eq('/')
    end

    it 'raises an error if unable to get mount path' do
      allow(subject).to receive(:cmd_exec).with('df "/path/to/file" | tail -1').and_raise(StandardError)
      expect { subject.get_mount_path('/path/to/file') }.to raise_error('Unable to get mount path of /path/to/file')
    end
  end

  describe '#ips' do
    it 'returns all IP addresses of the device' do
      # content from https://medium.com/@linuxadminhacks/find-the-names-of-the-network-interfaces-by-their-ips-4ef82326e49e
      fib_trie_content = "Main:\n  +-- 0.0.0.0/0 3 0 5\n    +-- 192.168.1.0/24 2 0 2\n        +-- 192.168.1.0/30 2 0 2\n           |-- 192.168.1.3\n              /32 host LOCAL"
      allow(subject).to receive(:read_file).with('/proc/net/fib_trie').and_return(fib_trie_content)
      expect(subject.ips).to eq(['192.168.1.3'])
    end
  end

  describe '#interfaces' do
    it 'returns all interfaces of the device' do
      interfaces_content = "/sys/class/net/eth0\n/sys/class/net/lo\n"
      allow(subject).to receive(:cmd_exec).with('for fn in /sys/class/net/*; do echo $fn; done').and_return(interfaces_content)
      expect(subject.interfaces).to eq(['eth0', 'lo'])
    end
  end

  describe '#macs' do
    it 'returns all MAC addresses of the device' do
      macs_content = "/sys/class/net/eth0\n/sys/class/net/lo\n"
      allow(subject).to receive(:cmd_exec).with('for fn in /sys/class/net/*; do echo $fn; done').and_return(macs_content)
      allow(subject).to receive(:read_file).with('/sys/class/net/eth0/address').and_return('00:11:22:33:44:55')
      allow(subject).to receive(:read_file).with('/sys/class/net/lo/address').and_return('00:00:00:00:00:00')
      allow(subject).to receive(:report_host)
      expect(subject.macs).to eq(['00:11:22:33:44:55', '00:00:00:00:00:00'])
    end
  end

  describe '#listen_tcp_ports' do
    it 'returns all listening TCP ports of the device' do
      tcp_content = "  0: 0100007F:0016 00000000:0000 0A\n"
      allow(subject).to receive(:read_file).with('/proc/net/tcp').and_return(tcp_content)
      expect(subject.listen_tcp_ports).to eq([22])
    end
  end

  describe '#listen_udp_ports' do
    it 'returns all listening UDP ports of the device' do
      udp_content = "  0: 0100007F:0035 00000000:0000 07\n"
      allow(subject).to receive(:read_file).with('/proc/net/udp').and_return(udp_content)
      expect(subject.listen_udp_ports).to eq([53])
    end
  end

  describe '#get_container_type' do
    it 'returns Docker if /.dockerenv exists' do
      allow(subject).to receive(:file?).with('/.dockerenv').and_return(true)
      allow(subject).to receive(:report_host)
      expect(subject.get_container_type).to eq('Docker')
    end

    it 'returns Docker if /.dockerinit exists' do
      allow(subject).to receive(:file?).with('/.dockerenv').and_return(false)
      allow(subject).to receive(:file?).with('/.dockerinit').and_return(true)
      allow(subject).to receive(:report_host)
      expect(subject.get_container_type).to eq('Docker')
    end

    it 'returns Podman if /run/.containerenv exists' do
      allow(subject).to receive(:file?).with('/.dockerenv').and_return(false)
      allow(subject).to receive(:file?).with('/.dockerinit').and_return(false)
      allow(subject).to receive(:file?).with('/run/.containerenv').and_return(true)
      allow(subject).to receive(:report_host)
      expect(subject.get_container_type).to eq('Podman')
    end

    it 'returns LXC if /dev/lxc exists' do
      allow(subject).to receive(:file?).with('/.dockerenv').and_return(false)
      allow(subject).to receive(:file?).with('/.dockerinit').and_return(false)
      allow(subject).to receive(:file?).with('/run/.containerenv').and_return(false)
      allow(subject).to receive(:directory?).with('/dev/lxc').and_return(true)
      allow(subject).to receive(:report_host)
      expect(subject.get_container_type).to eq('LXC')
    end

    it 'returns WSL if /proc/sys/kernel/osrelease contains WSL' do
      allow(subject).to receive(:file?).with('/.dockerenv').and_return(false)
      allow(subject).to receive(:file?).with('/.dockerinit').and_return(false)
      allow(subject).to receive(:file?).with('/run/.containerenv').and_return(false)
      allow(subject).to receive(:directory?).with('/dev/lxc').and_return(false)
      allow(subject).to receive(:file?).with('/proc/sys/kernel/osrelease').and_return(true)
      allow(subject).to receive(:read_file).with('/proc/sys/kernel/osrelease').and_return(['4.4.0-19041-Microsoft'])
      allow(subject).to receive(:report_host)
      expect(subject.get_container_type).to eq('WSL')
    end

    it 'returns Docker if /proc/1/cgroup contains docker' do
      allow(subject).to receive(:file?).with('/.dockerenv').and_return(false)
      allow(subject).to receive(:file?).with('/.dockerinit').and_return(false)
      allow(subject).to receive(:file?).with('/run/.containerenv').and_return(false)
      allow(subject).to receive(:directory?).with('/dev/lxc').and_return(false)
      allow(subject).to receive(:file?).with('/proc/sys/kernel/osrelease').and_return(false)
      allow(subject).to receive(:read_file).with('/proc/1/cgroup').and_return('1:name=systemd:/docker/1234567890abcdef')
      allow(subject).to receive(:report_host)
      expect(subject.get_container_type).to eq('Docker')
    end

    it 'returns LXC if /proc/1/cgroup contains lxc' do
      allow(subject).to receive(:file?).with('/.dockerenv').and_return(false)
      allow(subject).to receive(:file?).with('/.dockerinit').and_return(false)
      allow(subject).to receive(:file?).with('/run/.containerenv').and_return(false)
      allow(subject).to receive(:directory?).with('/dev/lxc').and_return(false)
      allow(subject).to receive(:file?).with('/proc/sys/kernel/osrelease').and_return(false)
      allow(subject).to receive(:read_file).with('/proc/1/cgroup').and_return('1:name=systemd:/lxc/1234567890abcdef')
      allow(subject).to receive(:report_host)
      expect(subject.get_container_type).to eq('LXC')
    end

    it 'returns Unknown if no container type is detected' do
      allow(subject).to receive(:file?).with('/.dockerenv').and_return(false)
      allow(subject).to receive(:file?).with('/.dockerinit').and_return(false)
      allow(subject).to receive(:file?).with('/run/.containerenv').and_return(false)
      allow(subject).to receive(:directory?).with('/dev/lxc').and_return(false)
      allow(subject).to receive(:file?).with('/proc/sys/kernel/osrelease').and_return(false)
      allow(subject).to receive(:read_file).with('/proc/1/cgroup').and_return('')
      allow(subject).to receive(:get_env).with('container').and_return(nil)
      allow(subject).to receive(:report_host)
      expect(subject.get_container_type).to eq('Unknown')
    end
  end
end
