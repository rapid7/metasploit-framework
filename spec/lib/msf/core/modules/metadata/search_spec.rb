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
    it { expect(described_class.parse_search_string(" ")).to eq({}) }
    it { expect(described_class.parse_search_string("os:osx os:windows")).to eq({"os"=>[["osx", "windows"], []]}) }
    it { expect(described_class.parse_search_string("postgres login")).to eq({"text"=>[["postgres", "login"], []]}) }
    it { expect(described_class.parse_search_string("platform:android")).to eq({"platform"=>[["android"], []]}) }
    it { expect(described_class.parse_search_string("platform:-android")).to eq({"platform"=>[[], ["android"]]}) }
    it { expect(described_class.parse_search_string("author:egypt arch:x64")).to eq({"author"=>[["egypt"], []], "arch"=>[["x64"], []]}) }
    it { expect(described_class.parse_search_string("  author:egypt   arch:x64  ")).to eq({"author"=>[["egypt"], []], "arch"=>[["x64"], []]}) }
  end

  describe '#find' do
    REF_TYPES = %w(CVE BID EDB)

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

    context 'on a module with the author "joev"' do
      let(:opts) { ({ 'author' => ['joev'] }) }
      accept = %w(author:joev author:joe)
      reject = %w(author:unrelated)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with the authors "joev" and "blarg"' do
      let(:opts) { ({ 'author' => ['joev', 'blarg'] }) }
      accept = %w(author:joev author:joe)
      reject = %w(author:sinn3r)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
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

    REF_TYPES.each do |ref_type|
      ref_num = '1234-1111'
      context 'on a module with reference #{ref_type}-#{ref_num}' do
        let(:opts) { ({ 'references' => ["#{ref_type}-#{ref_num}"] }) }
        accept = ["#{ref_type.downcase}:#{ref_num}"]
        reject = %w(1235-1111 1234-1112 bad).map { |n| "#{ref_type.downcase}:#{n}" }

        it_should_behave_like 'search_filter', :accept => accept, :reject => reject
      end
    end
  end
end
