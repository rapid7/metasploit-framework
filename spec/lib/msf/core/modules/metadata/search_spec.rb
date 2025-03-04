# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Modules::Metadata::Search do
  let(:mock_cache) do
    context_described_class = described_class
    Class.new do
      include context_described_class

      def get_metadata
        # mocked
      end
    end
  end

  subject { mock_cache.new }

  let(:default_opts) do
    {
      'name' => 'module',
      'fullname' => '/module',
      'mod_time' => '2020-08-14',
      'references' => ['cve-1234-1111'],
      'author' => %w(author1 author2)
    }
  end
  let(:opts) { {} }
  let(:mock_module) { Msf::Modules::Metadata::Obj.from_hash(default_opts.merge(opts)) }

  before(:each) do
    allow(subject).to receive(:get_metadata).and_return([mock_module])
  end

  describe '#parse_search_string' do
    it { expect(described_class.parse_search_string(nil)).to eq({}) }
    it { expect(described_class.parse_search_string("")).to eq({}) }
    it { expect(described_class.parse_search_string(" ")).to eq({}) }
    it { expect(described_class.parse_search_string("os:osx os:windows")).to eq({"os"=>[["osx", "windows"], []]}) }
    it { expect(described_class.parse_search_string("postgres login")).to eq({"text"=>[["postgres", "login"], []]}) }
    it { expect(described_class.parse_search_string("platform:android")).to eq({"platform"=>[["android"], []]}) }
    it { expect(described_class.parse_search_string("platform:-android")).to eq({"platform"=>[[], ["android"]]}) }
    it { expect(described_class.parse_search_string("author:egypt arch:x64")).to eq({"author"=>[["egypt"], []], "arch"=>[["x64"], []]}) }
    it { expect(described_class.parse_search_string("  author:egypt   arch:x64  ")).to eq({"author"=>[["egypt"], []], "arch"=>[["x64"], []]}) }
    it { expect(described_class.parse_search_string("postgres:")).to eq({"text"=>[["postgres"], []]}) }
    it { expect(described_class.parse_search_string("postgres;")).to eq({"text"=>[["postgres;"], []]}) }
    it { expect(described_class.parse_search_string("text:postgres:")).to eq({"text"=>[["postgres"], []]}) }
    it { expect(described_class.parse_search_string("postgres::::")).to eq({"text"=>[["postgres"], []]}) }
    it { expect(described_class.parse_search_string("turtle:bobcat postgres:")).to eq({"text"=>[["postgres"], []], "turtle"=>[["bobcat"], []]}) }
    it { expect(described_class.parse_search_string("stage:linux/x64/meterpreter ")).to eq({"stage"=>[["linux/x64/meterpreter"], []]}) }
    it { expect(described_class.parse_search_string("stager:linux/x64/reverse_tcp ")).to eq({"stager"=>[["linux/x64/reverse_tcp"], []]}) }
    it { expect(described_class.parse_search_string("adapter:cmd/linux/http/mips64 ")).to eq({"adapter"=>[["cmd/linux/http/mips64"], []]}) }
    it { expect(described_class.parse_search_string("session_type:PostgreSQL ")).to eq({"session_type"=>[["postgresql"], []]}) }
    it { expect(described_class.parse_search_string("session_type:MSSQL ")).to eq({"session_type"=>[["mssql"], []]}) }
    it { expect(described_class.parse_search_string("session_type:MySQL ")).to eq({"session_type"=>[["mysql"], []]}) }
    it { expect(described_class.parse_search_string("session_type:SMB ")).to eq({"session_type"=>[["smb"], []]}) }
    it { expect(described_class.parse_search_string("session_type:Meterpreter ")).to eq({"session_type"=>[["meterpreter"], []]}) }
    it { expect(described_class.parse_search_string("session_type:shell ")).to eq({"session_type"=>[["shell"], []]}) }
    it { expect(described_class.parse_search_string("action:forge_golden ")).to eq({"action"=>[["forge_golden"], []]}) }
    it { expect(described_class.parse_search_string("targets:windows ")).to eq({"targets"=>[["windows"], []]}) }
    it { expect(described_class.parse_search_string("targets:osx ")).to eq({"targets"=>[["osx"], []]}) }
    it { expect(described_class.parse_search_string("targets:ubuntu ")).to eq({"targets"=>[["ubuntu"], []]}) }
  end

  describe '#find' do
    REF_TYPES = %w(CVE BID EDB OSVDB)

    shared_examples "search_filter" do |opts|
      accept = opts[:accept] || []
      reject = opts[:reject] || []

      def find(search_string)
        search_params = described_class.parse_search_string(search_string)
        subject.find(search_params)
      end

      # inverse the query string. An input such as `os:osx` will be converted to the inverse, i.e. everything but osx `os:-osx`
      def inverse_query_terms(search_string)
        search_string.gsub(':', ':-')
      end

      accept.each do |query|
        it "should accept a query containing '#{query}'" do
          expect(find(query)).to eql([mock_module])
        end

        unless opts.has_key?(:test_inverse) and not opts[:test_inverse]
          it "should reject an inverse query containing of '#{query}'" do
            expect(find(inverse_query_terms(query))).to be_empty
          end
        end
      end

      reject.each do |query|
        it "should reject a query containing '#{query}'" do
          expect(find(query)).to be_empty
        end

        unless opts.has_key?(:test_inverse) and not opts[:test_inverse]
          it "should accept a query containing the inverse of '#{query}'" do
            expect(find(inverse_query_terms(query))).to eql([mock_module])
          end
        end
      end
    end

    let(:opts) { Hash.new }

    context 'on a blank query' do
      it_should_behave_like 'search_filter', :accept => [''], :test_inverse => false
    end

    context 'on a client module' do
      before do
        if subject.respond_to? :stance
          allow(subject).to receive(:stance).and_return('passive')
        else
          skip
        end
      end
      accept = %w(app:client)
      reject = %w(app:server)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a server module' do
      before do
        if subject.respond_to? :stance
          allow(subject).to receive(:stance).and_return('aggressive')
        else
          skip
          end
      end
      accept = %w(app:server)
      reject = %w(app:client)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with actions' do
      let(:opts) { ({ 'actions' => [{ 'name' => 'ACTION_NAME', 'description' => 'ACTION_DESCRIPTION'}] }) }
      accept = %w(action:action_name action:action_description)
      reject = %w(action:unrelated)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with the author "joev"' do
      let(:opts) { ({ 'author' => ['joev'] }) }
      accept = %w(author:joev author:joe)
      reject = %w(author:unrelated)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with a #author of nil' do
      let(:opts) { ({ 'author' => [nil] }) }
      reject = %w(author:foo)

      it_should_behave_like 'search_filter', :reject => reject
    end

    context 'on a module with the authors "joev" and "blarg"' do
      let(:opts) { ({ 'author' => ['joev', 'blarg'] }) }
      accept = %w(author:joev author:joe)
      reject = %w(author:sinn3r)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with a #stage_refname of "linux/x64/meterpreter"' do
      let(:opts) { { 'stage_refname' => 'linux/x64/meterpreter' } }
      accept = %w[stage:linux/x64/meterpreter]
      reject = %w[stage:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #stager_refname of "linux/x64/reverse_tcp"' do
      let(:opts) { { 'stager_refname' => 'linux/x64/reverse_tcp' } }
      accept = %w[stager:linux/x64/reverse_tcp]
      reject = %w[stager:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #adapter_refname of "cmd/linux/http/mips64"' do
      let(:opts) { { 'adapter_refname' => 'cmd/linux/http/mips64' } }
      accept = %w[adapter:cmd/linux/http/mips64]
      reject = %w[adapter:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #adapter_refname of "linux/x64/meterpreter_reverse_https"' do
      let(:opts) { { 'adapter_refname' => 'linux/x64/meterpreter_reverse_https' } }
      accept = %w[adapter:linux/x64/meterpreter_reverse_http adapter:linux/x64/meterpreter_reverse_https]
      reject = %w[adapter:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #session_type of ["postgresql"]' do
      let(:opts) { { 'session_types' => ['postgresql'] } }
      accept = %w[session_type:postgresql]
      accept_mis_spelt = %w[session_type:postgre]
      reject = %w[session_type:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
      it_should_behave_like 'search_filter', accept: accept_mis_spelt, reject: reject
    end

    context 'on a module with a #session_types of ["postgresql"]' do
      let(:opts) { { 'session_types' => ['postgresql'] } }
      accept = %w[session_type:postgre]
      reject = %w[session_type:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #session_type of ["mysql"]' do
      let(:opts) { { 'session_types' => ['mysql'] } }
      accept = %w[session_type:mysql]
      reject = %w[session_type:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #session_type of ["smb"]' do
      let(:opts) { { 'session_types' => ['smb'] } }
      accept = %w[session_type:SMB]
      reject = %w[session_type:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #session_type of ["mssql"]' do
      let(:opts) { { 'session_types' => ['mssql'] } }
      accept = %w[session_type:mssql]
      reject = %w[session_type:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #targets of ["windows"]' do
      let(:opts) { { 'targets' => ['windows'] } }
      accept = %w[targets:windows]
      reject = %w[targets:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #targets of ["osx"]' do
      let(:opts) { { 'targets' => ['osx'] } }
      accept = %w[targets:osx]
      reject = %w[targets:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #targets of ["ubuntu"]' do
      let(:opts) { { 'targets' => ['ubuntu'] } }
      accept = %w[targets:ubuntu]
      reject = %w[targets:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #targets of ["ubuntu", "windows", "osx"]' do
      let(:opts) { { 'targets' => %w[ubuntu windows osx] } }
      accept = %w[targets:osx]
      reject = %w[targets:unrelated]

      it_should_behave_like 'search_filter', accept: accept, reject: reject
    end

    context 'on a module with a #targets of nil' do
      let(:opts) { { 'targets' => nil } }

      reject = %w[targets:foo]

      it_should_behave_like 'search_filter', reject: reject
    end

    context 'on a module that supports the osx platform' do
      let(:opts) { ({ 'platform' => 'osx' }) }
      accept = %w(platform:osx os:osx)
      reject = %w(platform:bsd platform:windows platform:unix os:bsd os:windows os:unix)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module that supports the linux platform' do
      let(:opts) { ({ 'platform' => 'linux' }) }
      accept = %w(platform:linux os:linux)
      reject = %w(platform:bsd platform:windows platform:unix os:bsd os:windows os:unix)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module that supports the windows platform' do
      let(:opts) { ({ 'platform' => 'windows' }) }
      accept = %w(platform:windows os:windows)
      reject = %w(platform:bsd platform:osx platform:unix os:bsd os:osx os:unix)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module that supports the osx and linux platforms' do
      let(:opts) { ({ 'platform' => 'osx,linux' }) }
      accept = %w(platform:osx platform:linux os:osx os:linux)
      reject = %w(platform:bsd platform:windows platform:unix os:bsd os:windows os:unix)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module that supports the windows and irix platforms' do
      let(:opts) { ({ 'platform' => 'windows,irix' }) }
      accept = %w(platform:windows platform:irix os:windows os:irix)
      reject = %w(platform:bsd platform:osx platform:linux os:bsd os:osx os:linux)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with a default RPORT of 5555' do
      let(:opts) { { 'rport' => 5555 }}

      accept = %w(port:5555)
      reject = %w(port:5556)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with a #name of "blah"' do
      let(:opts) { ({ 'name' => 'blah' }) }
      it_should_behave_like 'search_filter', :accept => %w(text:blah), :reject => %w(text:foo)
      it_should_behave_like 'search_filter', :accept => %w(name:blah), :reject => %w(name:foo)
    end

    context 'on a module with a #fullname of "blah"' do
      let(:opts) { { 'fullname' => '/c/d/e/blah' }}
      it_should_behave_like 'search_filter', :accept => %w(text:blah), :reject => %w(text:foo)
      it_should_behave_like 'search_filter', :accept => %w(path:blah), :reject => %w(path:foo)
    end

    context 'on a module with a #description of "blah"' do
      let(:opts) { ({ 'description' => 'blah' }) }
      it_should_behave_like 'search_filter', :accept => %w(text:blah), :reject => %w(text:foo)
    end

    context 'on nil and empty input' do
      it_should_behave_like 'search_filter', :accept => [nil, '', '  '], :test_inverse => false
    end

    context 'on a module with a #description of "metasploit pro console"' do
      let(:opts) { ({ 'description' => 'metasploit pro console' }) }
      it_should_behave_like(
        'search_filter',
        :accept => ["metasploit", "metasploit pro", "metasploit pro console", "console pro"],
        :reject => ["metasploit framework", "pro framework", "pro console php"],
        :test_inverse => false
      )
    end

    context 'when invalid encodings are used, all results are returned' do
      context 'and the search term is present' do
        let(:opts) { ({ 'author' => ['István'.force_encoding("UTF-8")] }) }
        it_should_behave_like(
          'search_filter',
          accept: [
            "author:István",
            "author:Istv\xE1n ",
            "author:Istv\u00E1n ",
          ],
          :reject => [
            'different_author'
          ],
          :test_inverse => false
        )
      end
      context 'and the search term is not present' do
        let(:opts) { ({ 'author' => ['different_author'] }) }
        it_should_behave_like(
          'search_filter',
          accept: [
            'different_author',
            "author:Istv\xE1n",
          ],
          :reject => [
            "author:István",
            "author:Istv\u00E1n ",
          ],
          :test_inverse => false
        )
      end
    end

    context 'when filtering by module #type' do
      all_module_types = Msf::MODULE_TYPES
      all_module_types.each do |mtype|
        context "on a #{mtype} module" do
          let(:opts) { { 'type' => mtype } }

          accept = ["type:#{mtype}"]
          reject = all_module_types.reject { |t| t == mtype }.map { |t| "type:#{t}" }

          it_should_behave_like 'search_filter', :accept => accept, :reject => reject
        end
      end
    end

    context 'on a module with a #reference of nil' do
      let(:opts) { { 'references' => nil } }

      reject = %w[reference:foo]

      it_should_behave_like 'search_filter', reject: reject
    end

    REF_TYPES.each do |ref_type|
      ref_num = '1234-1111'
      context "on a module with reference #{ref_type}-#{ref_num}" do
        let(:opts) { ({ 'references' => ["#{ref_type}-#{ref_num}"] }) }
        accept = ["#{ref_type.downcase}:#{ref_num}"]
        reject = %w(1235-1111 1234-1112 bad).map { |n| "#{ref_type.downcase}:#{n}" }

        it_should_behave_like 'search_filter', :accept => accept, :reject => reject
      end
    end
  end
end
