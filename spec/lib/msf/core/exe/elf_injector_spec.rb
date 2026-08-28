require 'spec_helper'

RSpec.describe Msf::Exe::ElfInjector do
  def elf64(machine: 62, note_type: 4)
    code = "\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05".b
    entrypoint = 0x4000b0
    identifier = "\x7fELF\x02\x01\x01\x00".b + ("\x00".b * 8)
    header = identifier + [2, machine, 1, entrypoint, 64, 0, 0, 64, 56, 2, 0, 0, 0].pack('vvVQ<Q<Q<Vvvvvvv')
    load = [1, 5, 0, 0x400000, 0x400000, 176 + code.bytesize, 176 + code.bytesize, 0x1000].pack('VVQ<Q<Q<Q<Q<Q<')
    note = [note_type, 4, 176, entrypoint, entrypoint, 0, 0, 4].pack('VVQ<Q<Q<Q<Q<Q<')
    header + load + note + code
  end

  def elf32
    code = "\xb8\x01\x00\x00\x00\x31\xdb\xcd\x80".b
    entrypoint = 0x08048074
    identifier = "\x7fELF\x01\x01\x01\x00".b + ("\x00".b * 8)
    header = identifier + [2, 3, 1, entrypoint, 52, 0, 0, 52, 32, 2, 0, 0, 0].pack('vvVVVVVvvvvvv')
    load = [1, 0, 0x08048000, 0x08048000, 116 + code.bytesize, 116 + code.bytesize, 5, 0x1000].pack('V8')
    note = [4, 116, entrypoint, entrypoint, 0, 0, 4, 4].pack('V8')
    header + load + note + code
  end

  def elf64_with_code_cave
    code = "\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05".b
    entrypoint = 0x4000b0
    identifier = "\x7fELF\x02\x01\x01\x00".b + ("\x00".b * 8)
    header = identifier + [2, 62, 1, entrypoint, 64, 0, 0, 64, 56, 2, 0, 0, 0].pack('vvVQ<Q<Q<Vvvvvvv')
    executable = [1, 5, 0, 0x400000, 0x400000, 176 + code.bytesize, 176 + code.bytesize, 0x1000].pack('VVQ<Q<Q<Q<Q<Q<')
    readable = [1, 4, 0x1000, 0x401000, 0x401000, 1, 1, 0x1000].pack('VVQ<Q<Q<Q<Q<Q<')

    (header + executable + readable + code).ljust(0x1000, "\x00".b) + 'A'.b
  end

  it 'detects supported ELF architectures' do
    expect(described_class.new(template: elf32).architecture).to eq(:x86)
    expect(described_class.new(template: elf64).architecture).to eq(:x64)
    expect(described_class.new(template: elf64(machine: 183)).architecture).to eq(:aarch64)
  end

  it 'dispatches to each architecture-specific injector' do
    templates = [elf32, elf64, elf64(machine: 183)]

    templates.each do |template|
      generated = described_class.new(template: template, payload: "\xcc".b).generate
      expect(described_class.new(template: generated).injected?).to be(true)
    end
  end

  it 'adds a loadable segment and marks the result' do
    injector = described_class.new(template: elf64, payload: "\xcc".b)
    generated = injector.generate
    program_header_types = generated.byteslice(64, 112).unpack('VVQ<Q<Q<Q<Q<Q<VVQ<Q<Q<Q<Q<Q<').values_at(0, 8)

    expect(program_header_types).to eq([1, 1])
    expect(injector.technique).to eq(:program_header)
    expect(described_class.new(template: generated).injected?).to be(true)
  end

  it 'uses an executable code cave before requiring a reusable program header' do
    injector = described_class.new(template: elf64_with_code_cave, payload: "\xcc".b)
    generated = injector.generate

    expect(injector.technique).to eq(:code_cave)
    expect(generated.bytesize).to eq(elf64_with_code_cave.bytesize)
    expect(described_class.new(template: generated).injected?).to be(true)
  end

  it 'rejects ELF files without a reusable program header' do
    injector = described_class.new(template: elf64(note_type: 0x6474e553), payload: "\xcc".b)

    expect { injector.generate }.to raise_error(ArgumentError, 'ELF has no reusable PT_NULL or PT_NOTE program header')
  end

  it 'rejects non-ELF data' do
    expect { described_class.new(template: 'not an ELF') }.to raise_error(ArgumentError)
  end
end
