require 'spec_helper'
require 'rex/post/meterpreter/extensions/bofloader/bofloader'

RSpec.describe Rex::Post::Meterpreter::Extensions::Bofloader::Bofloader do
  let(:client) { double('Meterpreter client', arch: 'x64', register_extension_aliases: nil) }

  subject(:bofloader) { described_class.new(client) }

  it 'loads CNA state and resolves an invocation for the session architecture' do
    Dir.mktmpdir('bofloader-cna') do |directory|
      script_path = File.join(directory, 'commands.cna')
      File.binwrite(File.join(directory, 'hello.x64.o'), 'x64 BOF')
      File.binwrite(script_path, <<~'CNA')
        alias hello {
          $args = bof_pack($1, "zi", $2, 7);
          beacon_inline_execute($1, readb(openf(script_resource("hello. $+ $barch $+ .o")), -1), "go", $args);
        }
      CNA

      catalog = bofloader.load_cna(script_path)
      invocation = bofloader.cna_invocation('hello', arguments: ['world'])

      expect(catalog).to equal(bofloader.cna_catalog)
      expect(invocation).to include('data' => 'x64 BOF', 'entry' => 'go', 'format' => 'zi', 'values' => ['world', 7])
    end
  end

  it 'keeps the active catalog when reloading fails' do
    Dir.mktmpdir('bofloader-cna') do |directory|
      script_path = File.join(directory, 'commands.cna')
      File.binwrite(script_path, 'alias good { beacon_inline_execute($1, readb(openf(script_resource("good.o")), -1), "go", $null); }')
      catalog = bofloader.load_cna(script_path)
      File.binwrite(script_path, 'alias version { blog($1, "no BOF"); }')

      expect { bofloader.reload_cna }.to raise_error(Rex::Post::Meterpreter::Extensions::Bofloader::CnaParser::Error)
      expect(bofloader.cna_catalog).to equal(catalog)
    end
  end
end
