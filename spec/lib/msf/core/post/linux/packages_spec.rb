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
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'unsupported', version: '' })
        expect(subject.installed_package_version('test')).to be_nil
      end
    end

    # dockerfile for German locale Ubuntu
    # FROM ubuntu:latest
    #
    # # Install locales package and set up German locale
    # RUN apt-get update && apt-get install -y locales && \
    #     locale-gen de_DE.UTF-8 && \
    #     update-locale LANG=de_DE.UTF-8 && \
    #     echo "export LANG=de_DE.UTF-8" >> /etc/profile && \
    #     echo "export LANGUAGE=de_DE.UTF-8" >> /etc/profile && \
    #     echo "export LC_ALL=de_DE.UTF-8" >> /etc/profile
    #
    # # Set environment variables
    # ENV LANG=de_DE.UTF-8 \
    #     LANGUAGE=de_DE.UTF-8 \
    #     LC_ALL=de_DE.UTF-8
    #
    # CMD ["/bin/bash"]
    context 'when the Ubuntu/Debian package isnt installed' do
      it 'returns nil' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: 'Linux ubuntu22 5.15.0-25-generic #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux', distro: 'ubuntu', version: 'Ubuntu 22.04.5 LTS' })
        allow(subject).to receive(:cmd_exec).and_return('dpkg-query: no packages found matching example')
        expect(subject.installed_package_version('test')).to be_nil
      end
    end

    context 'when the Ubuntu/Debian package is installed' do
      it 'returns 3.5-5ubuntu2.1' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: 'Linux ubuntu22 5.15.0-25-generic #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux', distro: 'ubuntu', version: 'Ubuntu 22.04.5 LTS' })
        allow(subject).to receive(:cmd_exec).and_return('3.5-5ubuntu2.1')
        expect(subject.installed_package_version('test')).to eq(Rex::Version.new('3.5-5ubuntu2.1'))
      end
    end

    context 'when the Ubuntu/Debian package is installed with a + in the version number' do
      it 'returns 1.34.dfsg.pre.1ubuntu0.1.22.04.2' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: 'Linux ubuntu22 5.15.0-25-generic #25-Ubuntu SMP Wed Mar 30 15:54:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux', distro: 'ubuntu', version: 'Ubuntu 22.04.5 LTS' })
        allow(subject).to receive(:cmd_exec).and_return('1.34+dfsg-1ubuntu0.1.22.04.2')
        expect(subject.installed_package_version('test')).to eq(Rex::Version.new('1.34.dfsg.pre.1ubuntu0.1.22.04.2'))
      end
    end

    context 'when the Redhat or Fedora package is installed' do
      it 'returns 8.2.1-3.fc39' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'redhat', version: '' })
        allow(subject).to receive(:cmd_exec).and_return('curl-8.2.1-3.fc39.x86_64')
        expect(subject.installed_package_version('curl')).to eq(Rex::Version.new('8.2.1-3.fc39'))
      end
    end

    context 'when the Fedora package isnt installed' do
      it 'returns nil' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'fedora', version: '' })
        allow(subject).to receive(:cmd_exec).and_return('package foobar is not installed')
        expect(subject.installed_package_version('foobar')).to eq(nil)
      end
    end

    # dockerfile for German locale Fedora
    # FROM fedora:latest
    #
    # RUN dnf install -y glibc-langpack-de && \
    #     echo "export LANG=de_DE.UTF-8" >> /etc/profile && \
    #     echo "export LANGUAGE=de_DE.UTF-8" >> /etc/profile && \
    #     echo "export LC_ALL=de_DE.UTF-8" >> /etc/profile
    #
    # ENV LANG=de_DE.UTF-8 \
    #     LANGUAGE=de_DE.UTF-8 \
    #     LC_ALL=de_DE.UTF-8
    #
    # CMD ["/bin/bash"]
    context 'when the German language Fedora package isnt installed' do
      it 'returns nil' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'fedora', version: '' })
        allow(subject).to receive(:cmd_exec).and_return('Das Paket foobar ist nicht installiert')
        expect(subject.installed_package_version('foobar')).to eq(nil)
      end
    end

    # freebsd 12.0
    context 'when the FreeBSD package is installed' do
      it 'returns 1.12.0' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'freebsd', version: '' })
        allow(subject).to receive(:cmd_exec).and_return("pkg-1.12.0\nName           : pkg\nVersion        : 1.12.0")
        expect(subject.installed_package_version('test')).to eq(Rex::Version.new('1.12.0'))
      end
    end

    context 'when the FreeBSD package isnt installed' do
      it 'returns nil' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'freebsd', version: '' })
        allow(subject).to receive(:cmd_exec).and_return('pkg: No package(s) matching foobarbaz')
        expect(subject.installed_package_version('foobarbaz')).to eq(nil)
      end
    end

    # dockerfile for German locale gentoo
    # FROM gentoo/stage3

    # # Update system and install German locale support
    # RUN emerge --sync && \
    #     emerge --quiet --update --deep --newuse world && \
    #     echo "de_DE.UTF-8 UTF-8" >> /etc/locale.gen && \
    #     locale-gen && \
    #     eselect locale set de_DE.UTF-8 && \
    #     echo "export LANG=de_DE.UTF-8" >> /etc/profile && \
    #     echo "export LANGUAGE=de_DE.UTF-8" >> /etc/profile && \
    #     echo "export LC_ALL=de_DE.UTF-8" >> /etc/profile
    #
    # # Set environment variables
    # ENV LANG=de_DE.UTF-8 \
    #     LANGUAGE=de_DE.UTF-8 \
    #     LC_ALL=de_DE.UTF-8
    #
    # CMD ["/bin/bash"]
    context 'when the Gentoo package is installed and uses equery' do
      it 'returns 4.3.2-r3' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'gentoo', version: '' })
        allow(subject).to receive(:cmd_exec).and_return('sys-devel/gcc-4.3.2-r3')
        allow(subject).to receive(:command_exists?).with('equery').and_return(true)
        expect(subject.installed_package_version('test')).to eq(Rex::Version.new('4.3.2-r3'))
      end
    end

    context 'when the Gentoo package is installed and uses qlist' do
      it 'returns 4.3.2-r3' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'gentoo', version: '' })
        # equery and qlist output the same results for a found package
        allow(subject).to receive(:cmd_exec).and_return('sys-devel/gcc-4.3.2-r3')
        allow(subject).to receive(:command_exists?).with('equery').and_return(false)
        allow(subject).to receive(:command_exists?).with('qlist').and_return(true)
        expect(subject.installed_package_version('test')).to eq(Rex::Version.new('4.3.2-r3'))
      end
    end

    context 'when the Gentoo package isnt installed and uses qlist' do
      it 'returns nil' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'gentoo', version: '' })
        allow(subject).to receive(:command_exists?).with('equery').and_return(false)
        allow(subject).to receive(:command_exists?).with('qlist').and_return(true)
        allow(subject).to receive(:cmd_exec).and_return('')
        expect(subject.installed_package_version('test')).to eq(nil)
      end
    end

    context 'when the Arch package is installed' do
      it 'returns 8.12.1-1' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'arch', version: '' })
        allow(subject).to receive(:cmd_exec).and_return('Version         : 8.12.1-1')
        expect(subject.installed_package_version('test')).to eq(Rex::Version.new('8.12.1-1'))
      end
    end

    context 'when the Arch package isnt installed' do
      it 'returns nil' do
        allow(subject).to receive(:get_sysinfo).and_return({ kernel: '', distro: 'arch', version: '' })
        allow(subject).to receive(:cmd_exec).and_return('error: package \'test\' was not found')
        expect(subject.installed_package_version('test')).to eq(nil)
      end
    end
  end
end
