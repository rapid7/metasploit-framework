require 'spec_helper'

RSpec.describe Msf::Post::Linux::Packages do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Post::Linux::Packages)
    mod
  end

  describe '#installed_package_version' do
    context 'when the OS isnt supported' do
      it 'returns nil' do
        allow(subject).to receive(:get_sysinfo).and_return({:kernel=>"", :distro=>"unsupported", :version=>""})
        expect(subject.installed_package_version('test')).to be_nil
      end
    end

    context 'when the Ubuntu/Debian package isnt installed' do
      it 'returns nil' do
        allow(subject).to receive(:get_sysinfo).and_return({:kernel=>"Linux ubuntu22 5.15.0-25-generic #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux", :distro=>"ubuntu", :version=>"Ubuntu 22.04.5 LTS"})
        allow(subject).to receive(:cmd_exec).and_return('dpkg-query: no packages found matching example')
        expect(subject.installed_package_version('test')).to be_nil
      end
    end

    context 'when the Ubuntu/Debian package is installed' do
      it 'returns 3.5-5ubuntu2.1' do
        allow(subject).to receive(:get_sysinfo).and_return({:kernel=>"Linux ubuntu22 5.15.0-25-generic #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux", :distro=>"ubuntu", :version=>"Ubuntu 22.04.5 LTS"})
        allow(subject).to receive(:cmd_exec).and_return('ii  needrestart    3.5-5ubuntu2.1 all          check which daemons need to be restarted after library upgrades')
        expect(subject.installed_package_version('test')).to eq(Rex::Version.new('3.5-5ubuntu2.1'))
      end
    end

    context 'when the Ubuntu/Debian package is installed with a + in the version number' do
      it 'returns 1.34.dfsg.pre.1ubuntu0.1.22.04.2' do
        allow(subject).to receive(:get_sysinfo).and_return({:kernel=>"Linux ubuntu22 5.15.0-25-generic #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux", :distro=>"ubuntu", :version=>"Ubuntu 22.04.5 LTS"})
        allow(subject).to receive(:cmd_exec).and_return('ii  tar            1.34+dfsg-1ubuntu0.1.22.04.2 amd64        GNU version of the tar archiving utility')
        expect(subject.installed_package_version('test')).to eq(Rex::Version.new("1.34.dfsg.pre.1ubuntu0.1.22.04.2"))
      end
    end

    context 'when distro is redhat or fedora' do
      it 'returns the package version' do
        allow(subject).to receive(:get_sysinfo).and_return({:kernel=>"", :distro=>"redhat", :version=>""})
        allow(subject).to receive(:cmd_exec).and_return('curl-8.2.1-3.fc39.x86_64')
       expect(subject.installed_package_version('curl')).to eq(Rex::Version.new('8.2.1-3.fc39'))
      end
    end
  
    context 'when distro is solaris' do
      it 'returns the package version' do
        allow(subject).to receive(:get_sysinfo).and_return({:kernel=>"", :distro=>"solaris", :version=>""})
        allow(subject).to receive(:cmd_exec).and_return('State: Installed\nVersion: 1.2.3')
       expect(subject.installed_package_version('test')).to eq(Rex::Version.new('1.2.3'))
      end
    end
  
    context 'when distro is freebsd' do
      it 'returns the package version' do
        allow(subject).to receive(:get_sysinfo).and_return({:kernel=>"", :distro=>"freebsd", :version=>""})
        allow(subject).to receive(:cmd_exec).and_return('Version : 1.2.3')
       expect(subject.installed_package_version('test')).to eq(Rex::Version.new('1.2.3'))
      end
    end
  
    context 'when distro is gentoo' do
      it 'returns the package version' do
        allow(subject).to receive(:get_sysinfo).and_return({:kernel=>"", :distro=>"gentoo", :version=>""})
        allow(subject).to receive(:cmd_exec).and_return('sys-devel/gcc-4.3.2-r3')
       expect(subject.installed_package_version('test')).to eq(Rex::Version.new('4.3.2-r3'))
      end
    end
  
    context 'when distro is arch' do
      it 'returns the package version' do
        allow(subject).to receive(:get_sysinfo).and_return({:kernel=>"", :distro=>"arch", :version=>""})
        allow(subject).to receive(:cmd_exec).and_return('Version : 1.2.3')
       expect(subject.installed_package_version('test')).to eq(Rex::Version.new('1.2.3'))
      end
    end
  end
end
