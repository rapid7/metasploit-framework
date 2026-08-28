require 'spec_helper'
require 'rex/post/meterpreter/extensions/bofloader/cna_parser'

RSpec.describe Rex::Post::Meterpreter::Extensions::Bofloader::CnaParser do
  def parse_cna(script)
    Tempfile.create(['bofloader', '.cna']) do |file|
      file.write(script)
      file.flush
      return described_class.parse(path: file.path)
    end
  end

  it 'imports registered aliases and positional packing' do
    catalog = parse_cna(<<~'CNA')
      beacon_command_register("hello", "Display a greeting", "hello <message>");
      alias hello {
        $data = readb(openf(script_resource("hello. $+ $barch $+ .o")), -1);
        $args = bof_pack($1, "zi", $2, 1234);
        beacon_inline_execute($1, $data, "demo", $args);
      }
    CNA
    definition = catalog['bofs']['hello']

    expect(definition['description']).to eq('Display a greeting')
    expect(definition['entry']).to eq('demo')
    expect(definition['files']['x64']).to end_with('/hello.x64.o')
    expect(definition['files']['x86']).to end_with('/hello.x86.o')
    expect(definition['arguments'].map { |argument| argument['format'] }).to eq(%w[z i])
  end

  it 'resolves architecture-specific BOFs through conventional helper functions' do
    catalog = parse_cna(<<~'CNA')
      sub readbof {
        return readb(openf(script_resource("$2 $+ / $+ $2 $+ . $+ $barch $+ .o")), -1);
      }
      alias whoami {
        beacon_inline_execute($1, readbof($1, "whoami"), "go", $null);
      }
    CNA

    expect(catalog['bofs']['whoami']['files']['x64']).to end_with('/whoami/whoami.x64.o')
    expect(catalog['bofs']['whoami']['files']['x86']).to end_with('/whoami/whoami.x86.o')
  end

  it 'reports aliases with dynamic Aggressor behavior' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.x64.o")), -1), "go", $null);
      }
      alias dynamic {
        beacon_inline_execute($1, readb(openf(script_resource($2)), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/CNA alias 'dynamic' was skipped/)
  end

  it 'rejects scripts without compatible BOF aliases' do
    expect { parse_cna('alias version { blog($1, "no BOF"); }') }
      .to raise_error(described_class::Error, /No compatible BOFs found/)
  end

  it 'detects binary arguments read from local files' do
    catalog = parse_cna(<<~'CNA')
      alias load {
        $payload = readb(openf($2), -1);
        $args = bof_pack($1, "b", $payload);
        beacon_inline_execute($1, readb(openf(script_resource("load.o")), -1), "go", $args);
      }
    CNA

    expect(catalog['bofs']['load']['arguments'].first).to include('type' => 'file', 'position' => 0)
  end
end
