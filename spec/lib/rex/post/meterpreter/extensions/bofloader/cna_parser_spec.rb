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

  it 'resolves BOF path helpers nested in file-reading calls' do
    catalog = parse_cna(<<~'CNA')
      sub bof_path {
        return script_resource("$2 $+ .o");
      }
      alias example {
        beacon_inline_execute($1, readb(openf(bof_path($1, "right")), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs']['example']['files'].values).to all(end_with('/right.o'))
  end

  it 'uses the resource returned by a BOF helper' do
    catalog = parse_cna(<<~'CNA')
      sub readbof {
        $return = 1;
        $unused = script_resource("wrong.o");
        $path = script_resource("right.o");
        $handle = openf($path);
        $data = readb($handle, -1);
        if ($1) {
          blog($1, "Loading BOF");
        }
        return ($data);
      }
      alias example {
        beacon_inline_execute($1, readbof($1), "go", $null);
      }
    CNA

    expect(catalog['bofs']['example']['files'].values).to all(end_with('/right.o'))
  end

  it 'resolves variables exposed by BOF data wrappers' do
    catalog = parse_cna(<<~'CNA')
      alias example {
        $path = script_resource("right.o");
        $handle = openf($path);
        $data = readb($handle, -1);
        beacon_inline_execute($1, $data, "go", $null);
      }
    CNA

    expect(catalog['bofs']['example']['files'].values).to all(end_with('/right.o'))
  end

  it 'rejects BOF helpers with conditional return values' do
    expect do
      parse_cna(<<~'CNA')
        sub choose {
          if ($2 eq "wrong") {
            return script_resource("wrong.o");
          }
          return script_resource("right.o");
        }
        alias example {
          beacon_inline_execute($1, choose($1, $2), "go", $null);
        }
      CNA
    end.to raise_error(described_class::Error, /BOF helper does not have one static return value/)
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

  it 'detects binary file reads split across variables' do
    catalog = parse_cna(<<~'CNA')
      alias load {
        $handle = openf($2);
        $payload = readb($handle, -1);
        $args = bof_pack($1, "b", $payload);
        beacon_inline_execute($1, readb(openf(script_resource("load.o")), -1), "go", $args);
      }
    CNA

    expect(catalog['bofs']['load']['arguments'].first).to include('type' => 'file', 'position' => 0)
  end

  it 'rejects unsupported binary file read chains', :aggregate_failures do
    expressions = [
      'readb(openf($2), 4)',
      'readb(openf($2), -0x1)',
      'readb(openf($2), 08)',
      'readb(openf($2), side_effect($3))',
      'readb(openf($2))',
      'readb(openf($2), -1, 4)',
      'readb(openf($2, "rb"), -1)',
      'readb($2, -1)',
      'openf($2)',
      'openf(readb($2, -1))',
      'readb(readb(openf($2), -1), -1)',
      'readb(openf(openf($2)), -1)'
    ]

    expressions.each do |expression|
      expect do
        parse_cna(<<~CNA)
          alias load {
            $payload = #{expression};
            $args = bof_pack($1, "b", $payload);
            beacon_inline_execute($1, readb(openf(script_resource("load.o")), -1), "go", $args);
          }
        CNA
      end.to raise_error(described_class::Error, /binary file arguments must use/)
    end
  end

  it 'rejects an unsupported binary file read hidden behind variables' do
    expect do
      parse_cna(<<~'CNA')
        alias load {
          $handle = openf($2, "rb");
          $payload = readb($handle, -1);
          $args = bof_pack($1, "b", $payload);
          beacon_inline_execute($1, readb(openf(script_resource("load.o")), -1), "go", $args);
        }
      CNA
    end.to raise_error(described_class::Error, /binary file arguments must use/)
  end

  it 'rejects unsupported BOF data read chains', :aggregate_failures do
    expressions = [
      'readb(openf(script_resource("load.o")), 4)',
      'readb(openf(script_resource("load.o")), -0x1)',
      'readb(openf(script_resource("load.o")), 08)',
      'readb(openf(script_resource("load.o")), side_effect($2))',
      'readb(openf(script_resource("load.o")))',
      'readb(openf(script_resource("load.o")), -1, 4)',
      'readb(openf(script_resource("load.o"), "rb"), -1)',
      'readb(script_resource("load.o"), -1)',
      'openf(script_resource("load.o"))'
    ]

    expressions.each do |expression|
      expect do
        parse_cna(<<~CNA)
          alias load {
            beacon_inline_execute($1, #{expression}, "go", $null);
          }
        CNA
      end.to raise_error(described_class::Error, /BOF data must use/)
    end
  end

  it 'treats direct binary arguments as bytes' do
    catalog = parse_cna(<<~'CNA')
      alias echo {
        $args = bof_pack($1, "b", $2);
        beacon_inline_execute($1, readb(openf(script_resource("echo.o")), -1), "go", $args);
      }
    CNA

    expect(catalog['bofs']['echo']['arguments'].first).to include('type' => 'bytes', 'position' => 0)
  end

  it 'parses octal and hexadecimal integer literals' do
    catalog = parse_cna(<<~'CNA')
      alias example {
        $args = bof_pack($1, "iiiii", 010, 077, -010, 0x10, -0x10);
        beacon_inline_execute($1, readb(openf(script_resource("example.o")), -1), "go", $args);
      }
    CNA

    fixed_values = catalog['bofs']['example']['arguments'].map { |argument| argument['fixed'] }
    expect(fixed_values).to eq([8, 63, -8, 16, -16])
  end

  it 'rejects invalid octal integer literals' do
    expect do
      parse_cna(<<~'CNA')
        alias example {
          $args = bof_pack($1, "i", 08);
          beacon_inline_execute($1, readb(openf(script_resource("example.o")), -1), "go", $args);
        }
      CNA
    end.to raise_error(described_class::Error, /cannot statically evaluate packed expression 08/)
  end

  it 'accepts grouped bof_pack and iff calls' do
    catalog = parse_cna(<<~'CNA')
      alias example {
        $args = (bof_pack($1, "i", (iff(-istrue $2, $2, 7))));
        beacon_inline_execute($1, readb(openf(script_resource("example.o")), -1), "go", $args);
      }
    CNA

    expect(catalog['bofs']['example']['arguments'].first).to include('position' => 0, 'required' => false, 'default' => 7)
  end

  it 'uses the BOF resource passed to beacon_inline_execute' do
    catalog = parse_cna(<<~'CNA')
      alias example {
        $unused = readb(openf(script_resource("wrong.o")), -1);
        $data = readb(openf(script_resource("right.o")), -1);
        beacon_inline_execute($1, $data, "go", $null);
      }
    CNA

    expect(catalog['bofs']['example']['files'].values).to all(end_with('/right.o'))
  end

  it 'rejects compound expressions that resemble string literals' do
    expect do
      parse_cna(<<~'CNA')
        alias example {
          $args = bof_pack($1, "z", "hello" . "world");
          beacon_inline_execute($1, readb(openf(script_resource("example.o")), -1), "go", $args);
        }
      CNA
    end.to raise_error(described_class::Error, /cannot statically evaluate packed expression/)
  end

  it 'rejects iff calls wrapped in unsupported expressions' do
    expect do
      parse_cna(<<~'CNA')
        alias example {
          $args = bof_pack($1, "i", 1 + iff(-istrue $2, $2, 7));
          beacon_inline_execute($1, readb(openf(script_resource("example.o")), -1), "go", $args);
        }
      CNA
    end.to raise_error(described_class::Error, /cannot statically evaluate packed expression/)
  end
end
