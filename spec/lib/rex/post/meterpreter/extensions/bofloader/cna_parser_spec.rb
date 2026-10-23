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
        $barch = barch($1);
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
        $barch = barch($1);
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

  it 'does not mistake unrelated names ending in arch for architecture variables' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias dynamic {
        beacon_inline_execute($1, readb(openf(script_resource("$search.o")), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/BOF path still contains dynamic variables/)
  end

  it 'requires architecture variables to use the alias Beacon architecture' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias fixed_architecture {
        $arch = "x86";
        beacon_inline_execute($1, readb(openf(script_resource("fixed. $+ $arch $+ .o")), -1), "go", $null);
      }
      sub wrong_beacon {
        $barch = barch($2);
        return readb(openf(script_resource("wrong_beacon. $+ $barch $+ .o")), -1);
      }
      alias helper {
        beacon_inline_execute($1, wrong_beacon("not a Beacon", $3), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/\$arch must be assigned by barch/)
    expect(catalog['warnings']).to include(/\$barch must resolve the alias Beacon architecture/)
  end

  it 'ignores function-like text inside string literals' do
    catalog = parse_cna(<<~'CNA')
      blog($1, 'alias hidden { beacon_inline_execute($1, readb(openf(script_resource("hidden.o")), -1), "go", $null); }');
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias inert {
        blog($1, 'beacon_inline_execute($1, readb(openf(script_resource("inert.o")), -1), "go", $null)');
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
  end

  it 'ignores alias-like blocks nested in other declarations' do
    catalog = parse_cna(<<~'CNA')
      on beacon_initial {
        alias hidden {
          beacon_inline_execute($1, readb(openf(script_resource("hidden.o")), -1), "go", $null);
        }
      }
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
  end

  it 'rejects execution calls nested in control flow' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias guarded {
        if (-istrue $2) {
          beacon_inline_execute($1, readb(openf(script_resource("guarded.o")), -1), "go", $null);
        }
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/beacon_inline_execute must be an unconditional top-level call/)
  end

  it 'rejects execution calls embedded in other expressions' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias expression {
        $result = beacon_inline_execute($1, readb(openf(script_resource("expression.o")), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/beacon_inline_execute must be an unconditional top-level call/)
  end

  it 'rejects values assigned conditionally or mutated after assignment' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias conditional {
        if (-istrue $2) {
          $data = readb(openf(script_resource("conditional.o")), -1);
        }
        beacon_inline_execute($1, $data, "go", $null);
      }
      alias mutated {
        $data = readb(openf(script_resource("mutated.o")), -1);
        $data .= $2;
        beacon_inline_execute($1, $data, "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings'].length).to eq(2)
    expect(catalog['warnings']).to all(include('has a dynamic assignment'))
  end

  it 'rejects conditional helper returns' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      sub conditional {
        if (-istrue $2) {
          return readb(openf(script_resource("conditional.o")), -1);
        }
      }
      alias guarded {
        beacon_inline_execute($1, conditional($1, $2), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/BOF helper return must be unconditional and top-level/)
  end

  it 'rejects interpolated values that are presented as literals' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias dynamic_value {
        $args = bof_pack($1, "z", "hello $+ $2");
        beacon_inline_execute($1, readb(openf(script_resource("dynamic_value.o")), -1), "go", $args);
      }
      alias dynamic_entry {
        beacon_inline_execute($1, readb(openf(script_resource("dynamic_entry.o")), -1), "$2", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings'].length).to eq(2)
  end

  it 'requires calls to target the alias Beacon and rejects extra execution arguments' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias wrong_execute_beacon {
        beacon_inline_execute($2, readb(openf(script_resource("wrong_execute_beacon.o")), -1), "go", $null);
      }
      alias wrong_pack_beacon {
        $args = bof_pack($2, "z", $3);
        beacon_inline_execute($1, readb(openf(script_resource("wrong_pack_beacon.o")), -1), "go", $args);
      }
      alias extra {
        beacon_inline_execute($1, readb(openf(script_resource("extra.o")), -1), "go", $null, side_effect($2));
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/beacon_inline_execute must target the alias Beacon/)
    expect(catalog['warnings']).to include(/bof_pack must target the alias Beacon/)
    expect(catalog['warnings']).to include(/beacon_inline_execute has unsupported extra arguments/)
  end

  it 'rejects duplicate aliases and helpers' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias duplicate {
        beacon_inline_execute($1, readb(openf(script_resource("first.o")), -1), "go", $null);
      }
      alias duplicate {
        beacon_inline_execute($1, readb(openf(script_resource("second.o")), -1), "go", $null);
      }
      sub helper {
        return script_resource("first.o");
      }
      sub helper {
        return script_resource("second.o");
      }
      alias duplicate_helper {
        beacon_inline_execute($1, helper($1), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/CNA alias 'duplicate' is declared more than once/)
    expect(catalog['warnings']).to include(/BOF helper is declared more than once/)
  end

  it 'rejects scripts without compatible BOF aliases' do
    expect { parse_cna('alias version { blog($1, "no BOF"); }') }
      .to raise_error(described_class::Error, /No compatible BOFs found/)
  end
end

RSpec.describe Rex::Post::Meterpreter::Extensions::Bofloader::CnaParser do
  def parse_cna(script)
    Tempfile.create(['bofloader', '.cna']) do |file|
      file.write(script)
      file.flush
      return described_class.parse(path: file.path)
    end
  end

  it 'rejects execution calls guarded by an earlier return or throw' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias guarded_return {
        if (-istrue $2) {
          return;
        }
        beacon_inline_execute($1, readb(openf(script_resource("guarded_return.o")), -1), "go", $null);
      }
      alias guarded_throw {
        if (-istrue $2) {
          throw "unsupported target";
        }
        beacon_inline_execute($1, readb(openf(script_resource("guarded_throw.o")), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings'].length).to eq(2)
    expect(catalog['warnings']).to all(include('conditional return or throw can prevent beacon_inline_execute'))
  end

  it 'rejects reassigned positional arguments and Beacon IDs' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias reassigned_argument {
        $2 = uc($2);
        $args = bof_pack($1, "z", $2);
        beacon_inline_execute($1, readb(openf(script_resource("reassigned_argument.o")), -1), "go", $args);
      }
      alias reassigned_beacon {
        $1 = $2;
        beacon_inline_execute($1, readb(openf(script_resource("reassigned_beacon.o")), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/\$2 has a dynamic assignment/)
    expect(catalog['warnings']).to include(/beacon_inline_execute must target the alias Beacon/)
  end

  it 'decodes hexadecimal and Unicode escapes in parsed literals' do
    catalog = parse_cna(<<~'CNA')
      alias escaped {
        $args = bof_pack($1, "z", "A\x42C\u0044");
        beacon_inline_execute($1, readb(openf(script_resource("escaped.o")), -1), "go", $args);
      }
    CNA

    expect(catalog['bofs']['escaped']['arguments'].first['fixed']).to eq('ABCD')
  end

  it 'preserves hexadecimal byte escapes in fixed binary arguments' do
    catalog = parse_cna(<<~'CNA')
      alias escaped_bytes {
        $args = bof_pack($1, "bz", "\x00\x7f\x80\xff", "\x80\xff");
        beacon_inline_execute($1, readb(openf(script_resource("escaped_bytes.o")), -1), "go", $args);
      }
    CNA

    fixed_values = catalog['bofs']['escaped_bytes']['arguments'].map { |argument| argument['fixed'] }
    expect(fixed_values[0].bytes).to eq([0x00, 0x7f, 0x80, 0xff])
    expect(fixed_values[1].bytes).to eq([0xc2, 0x80, 0xc3, 0xbf])
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

  it 'preserves string literals assigned through variables' do
    catalog = parse_cna(<<~'CNA')
      alias echo {
        $message = "hello";
        $args = bof_pack($1, "z", $message);
        beacon_inline_execute($1, readb(openf(script_resource("echo.o")), -1), "go", $args);
      }
    CNA

    expect(catalog['bofs']['echo']['arguments'].first).to include('fixed' => 'hello')
  end

  it 'supports optional direct binary arguments' do
    catalog = parse_cna(<<~'CNA')
      alias echo {
        $args = bof_pack($1, "b", iff(-istrue $2, $2, ""));
        beacon_inline_execute($1, readb(openf(script_resource("echo.o")), -1), "go", $args);
      }
    CNA

    expect(catalog['bofs']['echo']['arguments'].first).to include(
      'type' => 'bytes', 'position' => 0, 'required' => false, 'default' => ''.b
    )
  end

  it 'uses explicit optional usage hints for direct positional arguments' do
    catalog = parse_cna(<<~'CNA')
      beacon_command_register("services", "Enumerate services", "services [opt: hostname]");
      alias services {
        $args = bof_pack($1, "z", $2);
        beacon_inline_execute($1, readb(openf(script_resource("services.o")), -1), "go", $args);
      }
    CNA

    expect(catalog['bofs']['services']['arguments'].first).to include(
      'name' => 'hostname', 'required' => false, 'default' => ''
    )
  end

  it 'does not treat usage names beginning with opt as optional markers' do
    catalog = parse_cna(<<~'CNA')
      beacon_command_register("demo", "Display an option", "demo <option>");
      alias demo {
        $args = bof_pack($1, "i", $2);
        beacon_inline_execute($1, readb(openf(script_resource("demo.o")), -1), "go", $args);
      }
    CNA

    expect(catalog['bofs']['demo']['arguments'].first).to include('name' => 'option', 'required' => true)
  end

  it 'rejects impractical positional values without materializing their range' do
    expect do
      parse_cna(<<~'CNA')
        alias example {
          $args = bof_pack($1, "z", $999999999999999999999);
          beacon_inline_execute($1, readb(openf(script_resource("example.o")), -1), "go", $args);
        }
      CNA
    end.to raise_error(described_class::Error, /CNA positional arguments are transformed outside bof_pack/)
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

  it 'rejects integer literals outside the packed format range' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias wide {
        $args = bof_pack($1, "i", 2147483648);
        beacon_inline_execute($1, readb(openf(script_resource("wide.o")), -1), "go", $args);
      }
      alias short {
        $args = bof_pack($1, "s", -32769);
        beacon_inline_execute($1, readb(openf(script_resource("short.o")), -1), "go", $args);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to all(include('argument has an incompatible literal'))
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

RSpec.describe Rex::Post::Meterpreter::Extensions::Bofloader::CnaParser do
  def parse_cna(script)
    Tempfile.create(['bofloader', '.cna']) do |file|
      file.write(script)
      file.flush
      return described_class.parse(path: file.path)
    end
  end

  it 'rejects assignments that occur after their values are consumed' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias late {
        beacon_inline_execute($1, $data, "go", $args);
        $data = readb(openf(script_resource("late.o")), -1);
        $args = bof_pack($1, "z", "after");
      }
      alias late_dependency {
        $path = script_resource("late_dependency. $+ $barch $+ .o");
        $barch = barch($1);
        $data = readb(openf($path), -1);
        beacon_inline_execute($1, $data, "go", $null);
      }
      alias mutated_named_value {
        $argument = $2;
        while $argument (producer()) { }
        beacon_inline_execute($1, readb(openf(script_resource("mutated_named_value.o")), -1), "go", bof_pack($1, "z", $argument));
      }
      alias redeclared_named_value {
        $data = readb(openf(script_resource("redeclared_named_value.o")), -1);
        global('$data');
        beacon_inline_execute($1, $data, "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/CNA alias 'late' was skipped: \$data has a dynamic assignment/)
    expect(catalog['warnings']).to include(/CNA alias 'late_dependency' was skipped: \$barch has a dynamic assignment/)
    expect(catalog['warnings']).to include(/CNA alias 'mutated_named_value' was skipped: \$argument has a dynamic assignment/)
    expect(catalog['warnings']).to include(/CNA alias 'redeclared_named_value' was skipped: \$data has a dynamic assignment/)
  end

  it 'rejects mutations of helper parameters used in resource paths' do
    catalog = parse_cna(<<~'CNA')
      sub mutated_path {
        $2 = "wrong";
        return readb(openf(script_resource("$2 $+ .o")), -1);
      }
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias mutated_helper {
        beacon_inline_execute($1, mutated_path($1, "right"), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/CNA alias 'mutated_helper' was skipped: \$2 has a dynamic assignment/)
  end

  it 'requires exactly one BOF content read across helper calls' do
    catalog = parse_cna(<<~'CNA')
      sub loaded_bof {
        return readb(openf(script_resource("loaded.o")), -1);
      }
      alias good {
        beacon_inline_execute($1, loaded_bof($1), "go", $null);
      }
      alias direct_path {
        beacon_inline_execute($1, script_resource("path.o"), "go", $null);
      }
      alias double_read {
        beacon_inline_execute($1, readb(openf(loaded_bof($1)), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings'].length).to eq(2)
    expect(catalog['warnings']).to all(include('BOF data must use exactly one readb(openf(path), -1)'))
  end

  it 'rejects alternate writes to positional parameters' do
    catalog = parse_cna(<<~'CNA')
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias tuple_write {
        ($1, $ignored) = @("different Beacon", 0);
        beacon_inline_execute($1, readb(openf(script_resource("tuple.o")), -1), "go", $null);
      }
      alias assignment_loop {
        while $2 (producer()) { }
        beacon_inline_execute($1, readb(openf(script_resource("loop.o")), -1), "go", bof_pack($1, "z", $2));
      }
      alias argument_array_write {
        @_[0] = "different Beacon";
        beacon_inline_execute($1, readb(openf(script_resource("argument_array_write.o")), -1), "go", $null);
      }
      alias argument_array_iteration {
        foreach $argument (@_) { $argument = "different"; }
        beacon_inline_execute($1, readb(openf(script_resource("argument_array_iteration.o")), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings'].count { |warning| warning.include?('beacon_inline_execute must target the alias Beacon') }).to eq(3)
    expect(catalog['warnings']).to include(/\$2 has a dynamic assignment/)
  end

  it 'rejects assertions and early exits in BOF helpers' do
    catalog = parse_cna(<<~'CNA')
      sub guarded_helper {
        if ($2) { throw "stop"; }
        return readb(openf(script_resource("guarded.o")), -1);
      }
      alias good {
        beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null);
      }
      alias asserted {
        assert size(@_) > 1;
        beacon_inline_execute($1, readb(openf(script_resource("asserted.o")), -1), "go", bof_pack($1, "z", $2));
      }
      alias guarded_helper_alias {
        beacon_inline_execute($1, guarded_helper($1, $2), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to eq(['good'])
    expect(catalog['warnings']).to include(/assert can prevent beacon_inline_execute/)
    expect(catalog['warnings']).to include(/flow control can prevent the BOF helper return/)
  end

  it 'does not treat inert control-flow words as early exits' do
    catalog = parse_cna(<<~'CNA')
      sub load_bof {
        %metadata = %(return => "value", throw => "value", assert => "value");
        return readb(openf(script_resource("helper.o")), -1);
      }
      alias direct {
        %metadata = %(return => "value", throw => "value", assert => "value");
        beacon_inline_execute($1, readb(openf(script_resource("direct.o")), -1), "go", $null);
      }
      alias helper {
        beacon_inline_execute($1, load_bof($1), "go", $null);
      }
    CNA

    expect(catalog['bofs'].keys).to contain_exactly('direct', 'helper')
  end

  it 'rejects scripts that override required importer functions' do
    expect do
      parse_cna(<<~'CNA')
        sub beacon_inline_execute {
          blog($1, "Not executing a BOF");
        }
        alias shadowed {
          beacon_inline_execute($1, readb(openf(script_resource("shadowed.o")), -1), "go", $null);
        }
      CNA
    end.to raise_error(described_class::Error, /overrides required functions: beacon_inline_execute/)
  end

  it 'allows valid aliases when an overridden intrinsic is not used by their import path' do
    catalog = parse_cna(<<~'CNA')
      sub iff {
        return "custom";
      }
      sub beacon_command_register {
        return;
      }
      beacon_command_register("example", "Not registration metadata", "example [opt: value]");
      alias example {
        beacon_inline_execute($1, readb(openf(script_resource("example.o")), -1), "go", bof_pack($1, "z", $2));
      }
    CNA

    expect(catalog['bofs']['example']).to include(
      'description' => a_string_starting_with('Imported from'),
      'usage' => 'example'
    )
    expect(catalog['bofs']['example']['arguments'].first).to include('required' => true)
  end

  it 'uses only top-level registrations to classify optional arguments' do
    catalog = parse_cna(<<~'CNA')
      beacon_command_register("metadata", "Active", "metadata <value>");
      if (false) {
        beacon_command_register("metadata", "Inactive", "metadata <opt:value>");
      }
      alias metadata {
        beacon_inline_execute($1, readb(openf(script_resource("metadata.o")), -1), "go", bof_pack($1, "z", $2));
      }
    CNA

    expect(catalog['bofs']['metadata']).to include('description' => 'Active', 'usage' => 'metadata <value>')
    expect(catalog['bofs']['metadata']['arguments'].first).to include('required' => true)
  end

  it 'handles quoted escapes without aborting compatible aliases' do
    catalog = parse_cna(<<~'CNA')
      beacon_command_register("escaped", "Smile: \uD83D\uDE00", "escaped");
      beacon_command_register("ignored", "\uD800", "ignored");
      alias escaped {
        beacon_inline_execute($1, readb(openf(script_resource("escaped.o")), -1), "go", bof_pack($1, "zz", 'a\\b', "\uD83D\uDE00"));
      }
      alias invalid_path {
        beacon_inline_execute($1, readb(openf(script_resource("bad\x00.o")), -1), "go", $null);
      }
      alias encoded_dollar {
        beacon_inline_execute($1, readb(openf(script_resource("static.\u0024barch.o")), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs']['escaped']['description']).to eq("Smile: \u{1F600}")
    expect(catalog['bofs']['escaped']['arguments'].map { |argument| argument['fixed'] }).to eq(['a\\b', "\u{1F600}"])
    expect(catalog['warnings']).to include(/CNA alias 'invalid_path' was skipped: BOF path contains a null byte/)
    expect(catalog['warnings']).to include(/CNA alias 'encoded_dollar' was skipped: BOF path contains an encoded dollar sign/)
  end

  it 'uses a readable BOF header before inferring architecture from its path' do
    Dir.mktmpdir do |directory|
      resource_directory = ::File.join(directory, 'x64')
      ::Dir.mkdir(resource_directory)
      ::File.binwrite(::File.join(resource_directory, 'example.o'), [0x014c].pack('v'))
      script_path = ::File.join(directory, 'example.cna')
      ::File.write(script_path, <<~'CNA')
        alias example {
          beacon_inline_execute($1, readb(openf(script_resource("x64/example.o")), -1), "go", $null);
        }
      CNA

      catalog = described_class.parse(path: script_path)

      expect(catalog['bofs']['example']['files'].keys).to eq(['x86'])
    end
  end

  it 'infers architecture from the path when the BOF cannot be read' do
    catalog = parse_cna(<<~'CNA')
      alias example {
        beacon_inline_execute($1, readb(openf(script_resource("x64/example.o")), -1), "go", $null);
      }
    CNA

    expect(catalog['bofs']['example']['files'].keys).to eq(['x64'])
  end
end
