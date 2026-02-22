require 'spec_helper'

RSpec.describe Msf::Post::Linux::Kernel do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Post::Linux::Kernel)
    mod
  end

  describe '#uname' do
    context 'it returns an ubuntu kernel' do
      it 'returns the kernel information' do
        allow(subject).to receive(:cmd_exec).and_return('Linux kali 6.11.2-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.11.2-1kali1 (2024-10-15) x86_64 GNU/Linux ')
        expect(subject.uname).to eq('Linux kali 6.11.2-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.11.2-1kali1 (2024-10-15) x86_64 GNU/Linux')
      end
    end
  end

  describe '#kernel_release' do
    context 'it returns an ubuntu kernel release' do
      it 'returns 6.11.2-amd64' do
        allow(subject).to receive(:cmd_exec).and_return('6.11.2-amd64 ')
        expect(subject.kernel_release).to eq('6.11.2-amd64')
      end
    end
  end

  describe '#kernel_version' do
    context 'it returns an ubuntu kernel version' do
      it 'returns 6.11.2-amd64' do
        allow(subject).to receive(:cmd_exec).and_return('#1 SMP PREEMPT_DYNAMIC Kali 6.11.2-1kali1 (2024-10-15) ')
        expect(subject.kernel_version).to eq('#1 SMP PREEMPT_DYNAMIC Kali 6.11.2-1kali1 (2024-10-15)')
      end
    end
  end

  describe '#kernel_name' do
    context 'it returns an ubuntu kernel name' do
      it 'returns Linux' do
        allow(subject).to receive(:cmd_exec).and_return('Linux ')
        expect(subject.kernel_name).to eq('Linux')
      end
    end
  end

  describe '#kernel_hardware' do
    context 'it returns an ubuntu kernel hardware' do
      it 'returns x86_64' do
        allow(subject).to receive(:cmd_exec).and_return('x86_64 ')
        expect(subject.kernel_hardware).to eq('x86_64')
      end
    end
  end

  describe '#kernel_arch' do
    context 'it returns an ubuntu kernel arch' do
      it 'returns x64' do
        allow(subject).to receive(:cmd_exec).and_return('x86_64 ')
        expect(subject.kernel_arch).to eq('x64')
      end
      it 'returns aarch64' do
        allow(subject).to receive(:cmd_exec).and_return('aarch64 ')
        expect(subject.kernel_arch).to eq('aarch64')
      end
      it 'returns aarch64' do
        allow(subject).to receive(:cmd_exec).and_return('arm ')
        expect(subject.kernel_arch).to eq('armle')
      end
      it 'returns x86' do
        allow(subject).to receive(:cmd_exec).and_return('i686 ')
        expect(subject.kernel_arch).to eq('x86')
      end
      it 'returns ppc' do
        allow(subject).to receive(:cmd_exec).and_return('ppc ')
        expect(subject.kernel_arch).to eq('ppc')
      end
      it 'returns ppc64' do
        allow(subject).to receive(:cmd_exec).and_return('ppc64 ')
        expect(subject.kernel_arch).to eq('ppc64')
      end
      it 'returns ppc64le' do
        allow(subject).to receive(:cmd_exec).and_return('ppc64le ')
        expect(subject.kernel_arch).to eq('ppc64le')
      end
      it 'returns mips' do
        allow(subject).to receive(:cmd_exec).and_return('mips ')
        expect(subject.kernel_arch).to eq('mips')
      end
      it 'returns mips64' do
        allow(subject).to receive(:cmd_exec).and_return('mips64 ')
        expect(subject.kernel_arch).to eq('mips64')
      end
      it 'returns sparc' do
        allow(subject).to receive(:cmd_exec).and_return('sparc ')
        expect(subject.kernel_arch).to eq('sparc')
      end
      it 'returns riscv32le' do
        allow(subject).to receive(:cmd_exec).and_return('riscv32 ')
        expect(subject.kernel_arch).to eq('riscv32le')
      end
      it 'returns riscv64le' do
        allow(subject).to receive(:cmd_exec).and_return('riscv64 ')
        expect(subject.kernel_arch).to eq('riscv64le')
      end
      it 'returns loongarch64' do
        allow(subject).to receive(:cmd_exec).and_return('loongarch64 ')
        expect(subject.kernel_arch).to eq('loongarch64')
      end
    end
  end

  describe '#kernel_rex_version' do
    [
      { release: '5.15.0-25-generic', expected: '5.15.0', label: 'Ubuntu' },
      { release: '5.13.0-37.42', expected: '5.13.0', label: 'Ubuntu (docker cgroup)' },
      { release: '4.14.355-275.572.amzn2.x86_64', expected: '4.14.355', label: 'Amazon Linux 2' },
      { release: '5.4.129-72.229.amzn2int.x86_64', expected: '5.4.129', label: 'Amazon Linux 2 (int)' },
      { release: '4.0.4-301.fc22.x86_64', expected: '4.0.4', label: 'Fedora' },
      { release: '3.10.0-1160.el7.x86_64', expected: '3.10.0', label: 'RHEL/CentOS' },
      { release: '6.11.2-amd64', expected: '6.11.2', label: 'Debian' },
      { release: '6.6.7-arch1-1', expected: '6.6.7', label: 'Arch Linux' },
      { release: '5.4.0', expected: '5.4.0', label: 'simple version (no suffix)' },
      { release: '5.14.21-150500.55.83-default', expected: '5.14.21', label: 'SUSE/openSUSE' },
      { release: '6.6.63-0-lts', expected: '6.6.63', label: 'Alpine Linux' },
    ].each do |test_case|
      context "with #{test_case[:label]} kernel (#{test_case[:release]})" do
        it "returns Rex::Version #{test_case[:expected]}" do
          allow(subject).to receive(:cmd_exec).and_return(test_case[:release])
          result = subject.kernel_rex_version
          expect(result).to be_a(Rex::Version)
          expect(result).to eq(Rex::Version.new(test_case[:expected]))
        end
      end
    end

    context 'when a pre-fetched release string is provided' do
      it 'uses the provided string instead of calling kernel_release' do
        expect(subject).not_to receive(:cmd_exec)
        result = subject.kernel_rex_version('5.15.0-25-generic')
        expect(result).to eq(Rex::Version.new('5.15.0'))
      end
    end

    context 'when kernel_release returns a blank string' do
      it 'returns nil' do
        allow(subject).to receive(:cmd_exec).and_return('')
        expect(subject.kernel_rex_version).to be_nil
      end
    end

    context 'when kernel_release returns nil' do
      it 'returns nil' do
        allow(subject).to receive(:cmd_exec).and_return(nil)
        expect(subject.kernel_rex_version).to be_nil
      end
    end

    context 'when the version string before the first hyphen is not parseable' do
      it 'returns nil' do
        result = subject.kernel_rex_version('xyz-not-a-version')
        expect(result).to be_nil
      end
    end

    context 'when version comparison is used' do
      it 'allows comparison with other Rex::Version objects' do
        allow(subject).to receive(:cmd_exec).and_return('5.15.0-25-generic')
        v = subject.kernel_rex_version
        expect(v).to be > Rex::Version.new('5.14.0')
        expect(v).to be < Rex::Version.new('5.16.0')
        expect(v).to eq(Rex::Version.new('5.15.0'))
      end
    end
  end
end
