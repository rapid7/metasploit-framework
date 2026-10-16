require 'spec_helper'
require 'rex/post/meterpreter/extensions/bofloader/cna_argument_parser'

RSpec.describe Rex::Post::Meterpreter::Extensions::Bofloader::CnaArgumentParser do
  it 'packs positionals and fixed values in CNA order' do
    arguments = [
      { 'type' => 'wstring', 'format' => 'Z', 'position' => 0, 'required' => true },
      { 'type' => 'int16', 'format' => 's', 'fixed' => 1, 'required' => false }
    ]

    expect(described_class.new(arguments: arguments).parse(['C:\\Windows']))
      .to eq('format' => 'Zs', 'values' => ['C:\\Windows', 1])
  end

  it 'reads local files used as binary arguments' do
    Tempfile.create('bofloader-data') do |file|
      file.binmode
      file.write("\x01\xff")
      file.flush
      arguments = [{ 'type' => 'file', 'format' => 'b', 'position' => 0, 'required' => true }]

      expect(described_class.new(arguments: arguments).parse([file.path]))
        .to eq('format' => 'b', 'values' => ["\x01\xff".b])
    end
  end

  it 'packs direct binary arguments as bytes' do
    arguments = [{ 'type' => 'bytes', 'format' => 'b', 'position' => 0, 'required' => true }]

    expect(described_class.new(arguments: arguments).parse(['hello']))
      .to eq('format' => 'b', 'values' => ['hello'.b])
  end

  it 'accepts integer defaults parsed from CNA literals' do
    arguments = [{ 'type' => 'int32', 'format' => 'i', 'position' => 0, 'required' => false, 'default' => 7 }]

    expect(described_class.new(arguments: arguments).parse([]))
      .to eq('format' => 'i', 'values' => [7])
  end

  it 'rejects extra positionals' do
    arguments = [{ 'type' => 'int32', 'format' => 'i', 'fixed' => 1, 'required' => false }]

    expect { described_class.new(arguments: arguments).parse(['unused']) }
      .to raise_error(described_class::Error, /expected at most 0/)
  end
end
