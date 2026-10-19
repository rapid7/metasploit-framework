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
    shstrtab = "\x00.text\x00.shstrtab\x00".b
    section_header_offset = 0x900
    identifier = "\x7fELF\x02\x01\x01\x00".b + ("\x00".b * 8)
    header = identifier + [2, 62, 1, entrypoint, 64, section_header_offset, 0, 64, 56, 2, 64, 3, 2].pack('vvVQ<Q<Q<Vvvvvvv')
    executable = [1, 5, 0, 0x400000, 0x400000, 176 + code.bytesize, 176 + code.bytesize, 0x1000].pack('VVQ<Q<Q<Q<Q<Q<')
    readable = [1, 4, 0x1000, 0x401000, 0x401000, 1, 1, 0x1000].pack('VVQ<Q<Q<Q<Q<Q<')
    sections = ("\x00".b * 64) +
               [1, 1, 6, entrypoint, 176, code.bytesize, 0, 0, 16, 0].pack('VVQ<Q<Q<Q<VVQ<Q<') +
               [7, 3, 0, 0, 0x800, shstrtab.bytesize, 0, 0, 1, 0].pack('VVQ<Q<Q<Q<VVQ<Q<')

    (header + executable + readable + code).ljust(0x800, "\x00".b) + shstrtab.ljust(0x100, "\x00".b) + sections.ljust(0x700, "\x00".b) + 'A'.b
  end

  def elf64_with_text(text)
    entrypoint = 0x4000b0
    shstrtab = "\x00.text\x00.shstrtab\x00".b
    shstrtab_offset = 176 + text.bytesize
    section_header_offset = (shstrtab_offset + shstrtab.bytesize + 7) & -8
    file_size = 176 + text.bytesize
    identifier = "\x7fELF\x02\x01\x01\x00".b + ("\x00".b * 8)
    header = identifier + [2, 62, 1, entrypoint, 64, section_header_offset, 0, 64, 56, 2, 64, 3, 2].pack('vvVQ<Q<Q<Vvvvvvv')
    load = [1, 5, 0, 0x400000, 0x400000, file_size, file_size, 0x1000].pack('VVQ<Q<Q<Q<Q<Q<')
    note = [4, 4, file_size, 0x400000 + file_size, 0x400000 + file_size, 0, 0, 4].pack('VVQ<Q<Q<Q<Q<Q<')
    sections = ("\x00".b * 64) +
               [1, 1, 6, entrypoint, 176, text.bytesize, 0, 0, 16, 0].pack('VVQ<Q<Q<Q<VVQ<Q<') +
               [7, 3, 0, 0, shstrtab_offset, shstrtab.bytesize, 0, 0, 1, 0].pack('VVQ<Q<Q<Q<VVQ<Q<')

    (header + load + note + text + shstrtab).ljust(section_header_offset, "\x00".b) + sections
  end

  def elf64_with_nobits_code_cave
    template = elf64
    section_header_offset = 0x200
    segment_file_end = template.bytesize
    segment_address_end = 0x400000 + segment_file_end

    template[40, 8] = [section_header_offset].pack('Q<')
    template[58, 2] = [64].pack('v')
    template[60, 2] = [2].pack('v')
    template[104, 8] = [segment_file_end + 0x100].pack('Q<')

    null_section = "\x00".b * 64
    bss_section = [0, 8, 3, segment_address_end, segment_file_end, 0x100, 0, 0, 8, 0].pack('VVQ<Q<Q<Q<VVQ<Q<')
    template.ljust(section_header_offset, "\x00".b) + null_section + bss_section
  end

  def elf64_with_overlapping_gnu_property_note
    code = "\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05".b
    note_data = "\x00".b * 16
    program_header_end = 64 + (3 * 56)
    entrypoint = 0x400000 + program_header_end + note_data.bytesize
    file_size = program_header_end + note_data.bytesize + code.bytesize
    identifier = "\x7fELF\x02\x01\x01\x00".b + ("\x00".b * 8)
    header = identifier + [2, 62, 1, entrypoint, 64, 0, 0, 64, 56, 3, 0, 0, 0].pack('vvVQ<Q<Q<Vvvvvvv')
    load = [1, 5, 0, 0x400000, 0x400000, file_size, file_size, 0x1000].pack('VVQ<Q<Q<Q<Q<Q<')
    note = [4, 4, program_header_end, 0x400000 + program_header_end, 0x400000 + program_header_end, note_data.bytesize, note_data.bytesize, 4].pack('VVQ<Q<Q<Q<Q<Q<')
    property = [0x6474e553, 4, program_header_end + 4, 0x400000 + program_header_end + 4, 0x400000 + program_header_end + 4, 8, 8, 4].pack('VVQ<Q<Q<Q<Q<Q<')
    header + load + note + property + note_data + code
  end

  it 'detects supported ELF architectures' do
    expect(described_class.new(template: elf32).architecture).to eq(:x86)
    expect(described_class.new(template: elf64).architecture).to eq(:x64)
    expect(described_class.new(template: elf64(machine: 183)).architecture).to eq(:aarch64)
  end

  it 'rejects mismatched ELF classes and machine architectures' do
    expect { described_class.new(template: elf64(machine: 3)) }.to raise_error(ArgumentError, 'unsupported ELF class and machine architecture combination')
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
    program_headers = generated.byteslice(64, 112).unpack('VVQ<Q<Q<Q<Q<Q<VVQ<Q<Q<Q<Q<Q<')

    expect(program_headers.values_at(0, 8)).to eq([1, 1])
    expect(program_headers.values_at(1, 9)).to eq([5, 7])
    expect(injector.technique).to eq(:program_header)
    expect(described_class.new(template: generated).injected?).to be(true)
  end

  it 'uses a binary-specific SHA-1 marker derived from the first 2080 .text bytes' do
    common_text = 'A'.b * described_class::FINGERPRINT_BYTES
    first = described_class.new(template: elf64_with_text(common_text + 'X'.b), payload: "\xcc".b)
    same_prefix = described_class.new(template: elf64_with_text(common_text + 'Y'.b), payload: "\xcc".b)
    changed_prefix = described_class.new(template: elf64_with_text('B'.b + common_text.byteslice(1..)), payload: "\xcc".b)

    expect(first.fingerprint).to eq(Digest::SHA1.hexdigest(common_text))
    expect(same_prefix.fingerprint).to eq(first.fingerprint)
    expect(changed_prefix.fingerprint).not_to eq(first.fingerprint)
    expect(first.generate.end_with?(first.fingerprint)).to be(true)
  end

  it 'uses an executable code cave before requiring a reusable program header' do
    injector = described_class.new(template: elf64_with_code_cave, payload: "\xcc".b)
    generated = injector.generate

    expect(injector.technique).to eq(:code_cave)
    expect(generated.byteslice(64, 8).unpack('VV').last).to eq(7)
    expect(generated.bytesize).to eq(elf64_with_code_cave.bytesize)
    expect(described_class.new(template: generated).injected?).to be(true)
  end

  it 'does not use an executable code cave occupied by an SHT_NOBITS section' do
    template = elf64_with_nobits_code_cave
    injector = described_class.new(template: template, payload: "\xcc".b)
    generated = injector.generate

    expect(injector.technique).to eq(:program_header)
    expect(generated.byteslice(64, 56)).to eq(template.byteslice(64, 56))
    expect(described_class.new(template: generated).injected?).to be(true)
  end

  it 'rejects ELF files without a reusable program header' do
    injector = described_class.new(template: elf64(note_type: 0x6474e553), payload: "\xcc".b)

    expect { injector.generate }.to raise_error(ArgumentError, 'ELF has no reusable PT_NULL or PT_NOTE program header')
  end

  it 'does not reuse a PT_NOTE containing a GNU property range' do
    injector = described_class.new(template: elf64_with_overlapping_gnu_property_note, payload: "\xcc".b)

    expect { injector.generate }.to raise_error(ArgumentError, 'ELF has no reusable PT_NULL or PT_NOTE program header')
  end

  it 'rejects non-ELF data' do
    expect { described_class.new(template: 'not an ELF') }.to raise_error(ArgumentError)
  end
end
