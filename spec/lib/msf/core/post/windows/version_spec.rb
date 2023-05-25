# -*- coding: binary -*-
require 'spec_helper'


RSpec.describe Msf::Post::Windows::Version do

  subject do
    context_described_class = described_class

    klass = Class.new(Msf::Post) do
      include context_described_class
    end

    klass.new
  end

  let(:xp_sp2_systeminfo) do
    'Host Name:                 SMASH-72A287D2F
OS Name:                   Microsoft Windows XP Professional
OS Version:                5.1.2600 Service Pack 2 Build 2600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Uniprocessor Free
Registered Owner:          smash
Registered Organization:   
Product ID:                76487-011-3892913-22389
Original Install Date:     12/6/2022, 2:27:30 PM
System Up Time:            0 Days, 0 Hours, 51 Minutes, 12 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 6 Model 158 Stepping 10 GenuineIntel ~2208 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+10:00) Canberra, Melbourne, Sydney
Total Physical Memory:     511 MB
Available Physical Memory: 338 MB
Virtual Memory: Max Size:  2,048 MB
Virtual Memory: Available: 2,006 MB
Virtual Memory: In Use:    42 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\\\SMASH-72A287D2F
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: File 1
                           [02]: Q147222
                           [03]: KB911164 - Update
NetWork Card(s):           1 NIC(s) Installed.
                           [01]: VMware Accelerated AMD PCNet Adapter
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.73.254
                                 IP address(es)
                                 [01]: 192.168.73.147'
  end

  let(:server2003_sp1_systeminfo) do
    'Host Name:                 SMASH-P7NPUUMTB
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 1 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          smash
Registered Organization:
Product ID:                69712-012-0000545-42062
Original Install Date:     12/7/2022, 12:43:01 PM
System Up Time:            N/A
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 6 Model 158 Stepping 10 GenuineIntel ~2207 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+10:00) Canberra, Melbourne, Sydney
Total Physical Memory:     383 MB
Available Physical Memory: 229 MB
Page File: Max Size:       932 MB
Page File: Available:      799 MB
Page File: In Use:         133 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\\\SMASH-P7NPUUMTB
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.73.254
                                 IP address(es)
                                 [01]: 192.168.73.148'
  end

  let(:server2008_sp2_systeminfo) do
    'Host Name:                 WIN2008DC
OS Name:                   Microsoftr Windows Serverr 2008 Standard
OS Version:                6.0.6002 Service Pack 2 Build 6002
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                92573-082-2500115-76258
Original Install Date:     7/7/2022, 9:49:59 AM
System Boot Time:          11/29/2022, 9:44:06 AM
System Manufacturer:       QEMU
System Model:              Standard PC (i440FX + PIIX, 1996)
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 15 Model 6 Stepping 1 GenuineIntel ~3392 Mhz
BIOS Version:              SeaBIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org, 4/1/2014
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+10:00) Canberra, Melbourne, Sydney
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,833 MB
Page File: Max Size:       8,363 MB
Page File: Available:      7,083 MB
Page File: In Use:         1,280 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    pod7.local
Logon Server:              \\WIN2008DC
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: KB955430
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.20.1
                                 IP address(es)
                                 [01]: 192.168.20.99
                                 [02]: fe80::4d31:5b50:425a:4df0'
  end

  let(:win10_systeminfo) do
    'Host Name:                 WIN10BASE                 
OS Name:                   Microsoft Windows 10 Pro                                                               
OS Version:                10.0.19045 N/A Build 19045
OS Manufacturer:           Microsoft Corporation     
OS Configuration:          Standalone Workstation                                                                 
OS Build Type:             Multiprocessor Free                                                                    
Registered Owner:          smash
Registered Organization:   
Product ID:                00331-20300-00000-AA252
Original Install Date:     10/05/2021, 5:43:57 PM
System Boot Time:          2/12/2022, 5:02:02 PM
System Manufacturer:       QEMU
System Model:              Standard PC (i440FX + PIIX, 1996)
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: Intel64 Family 15 Model 6 Stepping 1 GenuineIntel ~3392 Mhz
                           [02]: Intel64 Family 15 Model 6 Stepping 1 GenuineIntel ~3392 Mhz
BIOS Version:              SeaBIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org, 1/04/2014
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+10:00) Canberra, Melbourne, Sydney
Total Physical Memory:     10,239 MB
Available Physical Memory: 5,545 MB
Virtual Memory: Max Size:  11,839 MB
Virtual Memory: Available: 6,416 MB
Virtual Memory: In Use:    5,423 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\\\WIN10BASE
Hotfix(s):                 17 Hotfix(s) Installed.
                           [01]: KB5020613
                           [02]: KB4562830
                           [03]: KB4577586
                           [04]: KB4580325
                           [05]: KB5000736
                           [06]: KB5012170
                           [07]: KB5015684
                           [08]: KB5019959
                           [09]: KB5011352
                           [10]: KB5011651
                           [11]: KB5014032
                           [12]: KB5014035
                           [13]: KB5014671
                           [14]: KB5015895
                           [15]: KB5016705
                           [16]: KB5018506
                           [17]: KB5005699
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.20.1
                                 IP address(es)
                                 [01]: 192.168.20.230
                                 [02]: fe80::47ee:641f:d05d:34f6
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.'
  end

  let(:server2022_systeminfo) do
    'Host Name:                 twenty22
OS Name:                   Microsoft Windows Server 2022 Datacenter Azure Edition
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          N/A
Registered Organization:   N/A
Product ID:                00446-90000-00000-AA477
Original Install Date:     12/2/2022, 5:01:55 AM
System Boot Time:          12/2/2022, 5:02:20 AM
System Manufacturer:       Microsoft Corporation
System Model:              Virtual Machine
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 85 Stepping 4 GenuineIntel ~2095 Mhz
BIOS Version:              Microsoft Corporation Hyper-V UEFI Release v4.1, 5/10/2022
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC) Coordinated Universal Time
Total Physical Memory:     4,095 MB
Available Physical Memory: 1,753 MB
Virtual Memory: Max Size:  5,119 MB
Virtual Memory: Available: 2,794 MB
Virtual Memory: In Use:    2,325 MB
Page File Location(s):     D:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\\\twenty22
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB5020619
                           [02]: KB5012170
                           [03]: KB5019081
                           [04]: KB5017399
Network Card(s):           1 NIC(s) Installed.
                           [01]: Microsoft Hyper-V Network Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     168.63.129.16
                                 IP address(es)
                                 [01]: 10.1.0.4
                                 [02]: fe80::9232:386b:229f:402f
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.'
  end

  let(:server2012_systeminfo) do
    'Host Name:                 WIN2012DC
OS Name:                   Microsoft Windows Server 2012 Standard
OS Version:                6.2.9200 N/A Build 9200
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00184-30000-00001-AA641
Original Install Date:     8/09/2021, 3:22:39 AM
System Boot Time:          27/10/2022, 1:09:24 PM
System Manufacturer:       QEMU
System Model:              Standard PC (i440FX + PIIX, 1996)
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: Intel64 Family 15 Model 6 Stepping 1 GenuineIntel ~3392 Mhz
                           [02]: Intel64 Family 15 Model 6 Stepping 1 GenuineIntel ~3392 Mhz
BIOS Version:              SeaBIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org, 1/04/2014
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-au;English (Australia)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+10:00) Canberra, Melbourne, Sydney
Total Physical Memory:     5,095 MB
Available Physical Memory: 2,811 MB
Virtual Memory: Max Size:  5,927 MB
Virtual Memory: Available: 3,460 MB
Virtual Memory: In Use:    2,467 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    pod8.lan
Logon Server:              \\\\WIN2012DC
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: KB2999226
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.20.1
                                 IP address(es)
                                 [01]: 192.168.20.210
                                 [02]: fe80::3d4f:28f8:dff2:5b29
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.'
  end

  let(:server2008r2_sp1_systeminfo) do
    'Host Name:                 WIN-QL13MCNSIB2
OS Name:                   Microsoft Windows Server 2008 R2 Standard
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00477-179-0000007-84039
Original Install Date:     12/6/2022, 4:07:05 AM
System Boot Time:          12/5/2022, 8:23:53 PM
System Manufacturer:       QEMU
System Model:              Standard PC (i440FX + PIIX, 1996)
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: Intel64 Family 15 Model 6 Stepping 1 GenuineIntel ~3392 Mhz
                           [02]: Intel64 Family 15 Model 6 Stepping 1 GenuineIntel ~3392 Mhz
BIOS Version:              SeaBIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org, 4/1/2014
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,310 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,197 MB
Virtual Memory: In Use:    898 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\\\WIN-QL13MCNSIB2
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: KB976902
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.20.1
                                 IP address(es)
                                 [01]: 192.168.20.130
                                 [02]: fe80::1469:cb66:dc1d:78bc'
  end

  context "#systeminfo_parsed" do
    it "parses systeminfo on XP" do
      allow(subject).to receive(:cmd_exec) { xp_sp2_systeminfo }
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::XP_SP2)
      expect(version.windows_server?).to eq(false)
      expect(version.domain_controller?).to eq(false)
    end

    it "parses systeminfo on 2003" do
      allow(subject).to receive(:cmd_exec) { server2003_sp1_systeminfo }
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::Server2003_SP1)
      expect(version.windows_server?).to eq(true)
      expect(version.domain_controller?).to eq(false)
    end

    it "parses systeminfo on Win10" do
      allow(subject).to receive(:cmd_exec) { win10_systeminfo }
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::Win10_22H2)
      expect(version.windows_server?).to eq(false)
      expect(version.domain_controller?).to eq(false)
    end

    it "parses systeminfo on 2022" do
      allow(subject).to receive(:cmd_exec) { server2022_systeminfo }
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::Server2022)
      expect(version.windows_server?).to eq(true)
      expect(version.domain_controller?).to eq(false)
    end

    it "parses systeminfo on 2012" do
      allow(subject).to receive(:cmd_exec) { server2012_systeminfo }
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::Server2012)
      expect(version.windows_server?).to eq(true)
      expect(version.domain_controller?).to eq(true)
    end

    it "parses systeminfo on 2008R2" do
      allow(subject).to receive(:cmd_exec) { server2008r2_sp1_systeminfo }
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::Server2008_R2_SP1)
      expect(version.windows_server?).to eq(true)
      expect(version.domain_controller?).to eq(false)
    end

    it "parses systeminfo on 2008" do
      allow(subject).to receive(:cmd_exec) { server2008_sp2_systeminfo }
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::Server2008_SP2)
      expect(version.windows_server?).to eq(true)
      expect(version.domain_controller?).to eq(true)
    end

  end
end
