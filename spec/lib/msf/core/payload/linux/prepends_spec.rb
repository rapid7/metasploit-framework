require 'spec_helper'

RSpec.describe 'Linux payload prepends', :content do
  def prepend_object(prepends_module, enabled:)
    object = Object.new.extend(prepends_module)
    object.define_singleton_method(:datastore) do
      {
        'PayloadLinuxMinKernel' => '3.17',
        'PrependExecOnce' => enabled
      }
    end
    object.define_singleton_method(:staged?) { false }
    object
  end

  def disassembled_instruction_names(processor, bytes)
    Metasm::Shellcode.disassemble(processor, bytes, 0).decoded.sort.map { |_address, instruction| instruction.instruction.opname }
  end

  def legacy_instruction_names
    {
      x86: {
        'PrependFork' => %w[push pop int test jz xor mov int mov int push pop int test jnz],
        'PrependSetresuid' => %w[xor xor mul mov int],
        'PrependSetreuid' => %w[xor xor push pop int],
        'PrependSetuid' => %w[xor push pop int],
        'PrependSetresgid' => %w[xor xor mul mov int],
        'PrependSetregid' => %w[xor xor push pop int],
        'PrependSetgid' => %w[xor push pop int],
        'PrependChrootBreak' => %w[xor xor push pop int push mov push pop int mov pop int xor push push.i16 mov push pop mov int loop push mov pop int],
        'AppendExit' => %w[xor push pop int]
      },
      x64: {
        'PrependFork' => %w[push pop syscall test jz xor push pop syscall add syscall push pop syscall test jnz],
        'PrependSetresuid' => %w[xor mov push pop syscall],
        'PrependSetreuid' => %w[xor mov mov push pop syscall],
        'PrependSetuid' => %w[xor push pop syscall],
        'PrependSetresgid' => %w[xor mov push pop syscall],
        'PrependSetregid' => %w[xor mov mov push pop syscall],
        'PrependSetgid' => %w[xor push pop syscall],
        'PrependChrootBreak' => %w[xor mov mov mov syscall mov push push mov mov push pop syscall xor mov mov syscall mov push mov push pop push pop syscall dec jnz push mov mov syscall],
        'AppendExit' => %w[xor push pop syscall]
      },
      aarch64: {
        'PrependSetuid' => %w[mov mov svc],
        'PrependSetreuid' => %w[mov mov mov svc],
        'PrependSetresuid' => %w[mov mov mov mov svc]
      }
    }
  end

  def legacy_prepend_hex
    {
      x86: {
        'PrependFork' => '6a0258cd8085c0740631c0b001cd80b042cd806a0258cd8085c075ed',
        'PrependSetresuid' => '31c931dbf7e3b0a4cd80',
        'PrependSetreuid' => '31c931db6a4658cd80',
        'PrependSetuid' => '31db6a1758cd80',
        'PrependSetresgid' => '31c931dbf7e3b0aacd80',
        'PrependSetregid' => '31c931db6a4758cd80',
        'PrependSetgid' => '31db6a2e58cd80',
        'PrependChrootBreak' => '31c931db6a4658cd806a3d89e36a2758cd8089d958cd8031c05066682e2e89e36a3d59b00ccd80e2fa6a3d89d958cd80',
        'AppendExit' => '31db6a0158cd80'
      },
      x64: {
        'PrependFork' => '6a39580f054885c074084831ff6a3c580f0504700f056a39580f054885c075ea',
        'PrependSetresuid' => '4831ff4889fe6a75580f05',
        'PrependSetreuid' => '4831ff4889fe4889f26a71580f05',
        'PrependSetuid' => '4831ff6a69580f05',
        'PrependSetresgid' => '4831ff4889fe6a77580f05',
        'PrependSetregid' => '4831ff4889fe4889f26a72580f05',
        'PrependSetgid' => '4831ff6a6a580f05',
        'PrependChrootBreak' => '4831ff4889fe4889f8b0710f0548bf616263646566676856574889e766beed016a53580f054831d2b2a14889d00f0566be2e2e564889e76a455b6a50580f05fecb75f76a2e4889e74889d00f05',
        'AppendExit' => '4831ff6a3c580f05'
      },
      aarch64: {
        'PrependSetuid' => 'e0031faa481280d2010000d4',
        'PrependSetreuid' => 'e0031faae1031faa281280d2010000d4',
        'PrependSetresuid' => 'e0031faae1031faae2031faa681280d2010000d4'
      }
    }
  end

  {
    x86: [Msf::Payload::Linux::X86::Prepends, Metasm::Ia32.new],
    x64: [Msf::Payload::Linux::X64::Prepends, Metasm::X64.new],
    aarch64: [Msf::Payload::Linux::Aarch64::Prepends, Metasm::ARM64.new]
  }.each do |architecture, (prepends_module, processor)|
    context architecture do
      it 'generates every prepend and append' do
        object = prepend_object(prepends_module, enabled: false)
        generated = object.prepends_map.merge(object.appends_map)

        expect(generated).not_to be_empty
        expect(generated.values).to all(be_a(String))
        expect(generated.values).not_to include('')
      end

      it 'preserves the legacy instruction sequences' do
        allow(Rex::Text).to receive(:rand_text_alpha).and_return('abcdefgh')
        generated = prepend_object(prepends_module, enabled: false).prepends_map.merge(prepend_object(prepends_module, enabled: false).appends_map)
        generated.delete('PrependExecOnce')

        expect(generated.keys).to contain_exactly(*legacy_instruction_names.fetch(architecture).keys)
        generated.each do |name, bytes|
          expect(disassembled_instruction_names(processor, bytes)).to eq(legacy_instruction_names.fetch(architecture).fetch(name))
          expect(bytes.unpack1('H*')).to eq(legacy_prepend_hex.fetch(architecture).fetch(name))
        end
      end

      it 'applies a first prepend containing a volatile marker path' do
        baseline = 'PAYLOAD'.b
        guarded = prepend_object(prepends_module, enabled: true).apply_prepends(baseline.dup)

        expect(prepend_object(prepends_module, enabled: false).apply_prepends(baseline.dup)).to eq(baseline)
        expect(prepends_module.instance_method(:prepends_order).bind(Object.new).call.first).to eq('PrependExecOnce')
        expect(guarded.bytesize).to be > baseline.bytesize
        expect(guarded).to include('/dev/shm/.msf-')
        expect(guarded).to end_with(baseline)
      end

      it 'creates the marker exclusively, continues on success, and exits for an existing marker' do
        object = prepend_object(prepends_module, enabled: true)
        object.define_singleton_method(:prepend_exec_once_path) { '/dev/shm/.msf-aaaaaaaaaaaa' }
        bytes = object.prepends_map.fetch('PrependExecOnce')
        decoded = Metasm::Shellcode.disassemble(processor, bytes, 0).decoded.transform_values { |instruction| instruction.instruction.to_s }

        case architecture
        when :x86
          expect(decoded.values_at(3, 8, 0xd)).to eq(['mov ecx, 0c1h', 'mov edx, 180h', 'mov eax, 5'])
          expect(decoded.values_at(0x16, 0x21, 0x25)).to eq(['js loc_23h', 'jmp loc_4ch', 'mov eax, 1'])
        when :x64
          expect(decoded.values_at(8, 0xd, 0x13)).to eq(['mov edx, 0c1h', 'mov r10d, 180h', 'mov eax, 101h'])
          expect(decoded.values_at(0x1c, 0x27, 0x2b)).to eq(['js loc_29h', 'jmp loc_52h', 'mov eax, 3ch'])
        when :aarch64
          expect(decoded.values_at(8, 0xc, 0x10)).to eq(['mov x2, 0c1h', 'mov x3, 180h', 'mov x8, 38h'])
          expect(decoded.values_at(0x1c, 0x28, 0x30)).to eq(['blt loc_2ch', 'b loc_54h', 'mov x8, 5dh'])
        end
      end
    end
  end
end
