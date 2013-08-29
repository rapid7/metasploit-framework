# -*- coding:binary -*-
require 'spec_helper'
require 'msf/core/module'
require 'msf/core/module/platform_list'

shared_examples "search_filter" do |opts|
  accept = opts[:accept] || []
  reject = opts[:reject] || []

  accept.each do |query|
    it "should accept a query containing '#{query}'" do
      # if the subject matches, search_filter returns false ("don't filter me out!")
      subject.search_filter(query).should be_false
    end

    unless opts.has_key?(:test_inverse) and not opts[:test_inverse]
      it "should reject a query containing '-#{query}'" do
        subject.search_filter("-#{query}").should be_true
      end
    end
  end

  reject.each do |query|
    it "should reject a query containing '#{query}'" do
      # if the subject doesn't matches, search_filter returns true ("filter me out!")
      subject.search_filter(query).should be_true
    end

    unless opts.has_key?(:test_inverse) and not opts[:test_inverse]
      it "should accept a query containing '-#{query}'" do
        subject.search_filter("-#{query}").should be_true # what? why?
      end
    end
  end
end


REF_TYPES = %w(CVE BID OSVDB EDB)

describe Msf::Module do
  describe '#search_filter' do
    let(:opts) { Hash.new }
    before { subject.stub(:fullname => '/module') }
    subject { Msf::Module.new(opts) }
    accept = []
    reject = []

    context 'on a blank query' do
      it_should_behave_like 'search_filter', :accept => [''], :test_inverse => false
    end

    context 'on a client module' do
      before { subject.stub(:stance => 'passive') }
      accept = %w(app:client)
      reject = %w(app:server)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a server module' do
      before { subject.stub(:stance => 'aggressive') }
      accept = %w(app:server)
      reject = %w(app:client)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with the author "joev"' do
      let(:opts) { ({ 'Author' => ['joev'] }) }
      accept = %w(author:joev author:joe)
      reject = %w(author:unrelated)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with the authors "joev" and "blarg"' do
      let(:opts) { ({ 'Author' => ['joev', 'blarg'] }) }
      accept = %w(author:joev author:joe)
      reject = %w(author:sinn3r)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module that supports the osx platform' do
      let(:opts) { ({ 'Platform' => %w(osx) }) }
      accept = %w(platform:osx os:osx)
      reject = %w(platform:bsd platform:windows platform:unix os:bsd os:windows os:unix)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module that supports the linux platform' do
      let(:opts) { ({ 'Platform' => %w(linux) }) }
      accept = %w(platform:linux os:linux)
      reject = %w(platform:bsd platform:windows platform:unix os:bsd os:windows os:unix)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module that supports the windows platform' do
      let(:opts) { ({ 'Platform' => %w(windows) }) }
      accept = %w(platform:windows os:windows)
      reject = %w(platform:bsd platform:osx platform:unix os:bsd os:osx os:unix)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module that supports the osx and linux platforms' do
      let(:opts) { ({ 'Platform' => %w(osx linux) }) }
      accept = %w(platform:osx platform:linux os:osx os:linux)
      reject = %w(platform:bsd platform:windows platform:unix os:bsd os:windows os:unix)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module that supports the windows and irix platforms' do
      let(:opts) { ({ 'Platform' => %w(windows irix) }) }
      accept = %w(platform:windows platform:irix os:windows os:irix)
      reject = %w(platform:bsd platform:osx platform:linux os:bsd os:osx os:linux)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with a default RPORT of 5555' do
      before { subject.stub(:datastore => { 'RPORT' => 5555 }) }
      accept = %w(port:5555)
      reject = %w(port:5556)

      it_should_behave_like 'search_filter', :accept => accept, :reject => reject
    end

    context 'on a module with a #name of "blah"' do
      let(:opts) { ({ 'Name' => 'blah' }) }
      it_should_behave_like 'search_filter', :accept => %w(text:blah), :reject => %w(text:foo)
      it_should_behave_like 'search_filter', :accept => %w(name:blah), :reject => %w(name:foo)
    end

    context 'on a module with a #fullname of "blah"' do
      before { subject.stub(:fullname => '/c/d/e/blah') }
      it_should_behave_like 'search_filter', :accept => %w(text:blah), :reject => %w(text:foo)
      it_should_behave_like 'search_filter', :accept => %w(path:blah), :reject => %w(path:foo)
    end

    context 'on a module with a #description of "blah"' do
      let(:opts) { ({ 'Description' => 'blah' }) }
      it_should_behave_like 'search_filter', :accept => %w(text:blah), :reject => %w(text:foo)
    end

    context 'when filtering by module #type' do
      all_module_types = Metasploit::Model::Module::Type::ALL
      all_module_types.each do |mtype|
        context "on a #{mtype} module" do
          before(:each) { subject.stub(:type => mtype) }

          accept = ["type:#{mtype}"]
          reject = all_module_types.reject { |t| t == mtype }.map { |t| "type:#{t}" }

          it_should_behave_like 'search_filter', :accept => accept, :reject => reject
        end
      end
    end

    REF_TYPES.each do |ref_type|
      ref_num = '1234-1111'
      context 'on a module with reference #{ref_type}-#{ref_num}' do
        let(:opts) { ({ 'References' => [[ref_type, ref_num]] }) }
        accept = ["#{ref_type.downcase}:#{ref_num}"]
        reject = %w(1235-1111 1234-1112 bad).map { |n| "#{ref_type.downcase}:#{n}" }

        it_should_behave_like 'search_filter', :accept => accept, :reject => reject
      end
    end
  end
end
