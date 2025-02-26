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
end
