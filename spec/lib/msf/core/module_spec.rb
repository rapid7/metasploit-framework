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
      subject.search_filter(query).should be_falsey
    end

    unless opts.has_key?(:test_inverse) and not opts[:test_inverse]
      it "should reject a query containing '-#{query}'" do
        subject.search_filter("-#{query}").should be_truthy
      end
    end
  end

  reject.each do |query|
    it "should reject a query containing '#{query}'" do
      # if the subject doesn't matches, search_filter returns true ("filter me out!")
      subject.search_filter(query).should be_truthy
    end

    unless opts.has_key?(:test_inverse) and not opts[:test_inverse]
      it "should accept a query containing '-#{query}'" do
        subject.search_filter("-#{query}").should be_truthy # what? why?
      end
    end
  end
end


REF_TYPES = %w(CVE BID OSVDB EDB)

describe Msf::Module do

  it { is_expected.to respond_to :[] }
  it { is_expected.to respond_to :[]= }
  it { is_expected.to respond_to :alias }
  it { is_expected.to respond_to :arch? }
  it { is_expected.to respond_to :arch_to_s }
  it { is_expected.to respond_to :author_to_s }
  it { is_expected.to respond_to :auxiliary? }
  it { is_expected.to respond_to :check }
  it { is_expected.to respond_to :comm }
  it { is_expected.to respond_to :compat }
  it { is_expected.to respond_to :compatible? }
  it { is_expected.to respond_to :debugging? }
  it { is_expected.to respond_to :description }
  it { is_expected.to respond_to :disclosure_date }
  it { is_expected.to respond_to :each_arch }
  it { is_expected.to respond_to :each_author }
  it { is_expected.to respond_to :encoder? }
  it { is_expected.to respond_to :exploit? }
  it { is_expected.to respond_to :fail_with }
  it { is_expected.to respond_to :file_path }
  it { is_expected.to respond_to :framework }
  it { is_expected.to respond_to :fullname }
  it { is_expected.to respond_to :import_defaults }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :nop? }
  it { is_expected.to respond_to :orig_cls }
  it { is_expected.to respond_to :owner }
  it { is_expected.to respond_to :payload? }
  it { is_expected.to respond_to :platform? }
  it { is_expected.to respond_to :platform_to_s }
  it { is_expected.to respond_to :post? }
  it { is_expected.to respond_to :print_error }
  it { is_expected.to respond_to :print_good }
  it { is_expected.to respond_to :print_line }
  it { is_expected.to respond_to :print_line_prefix }
  it { is_expected.to respond_to :print_prefix }
  it { is_expected.to respond_to :print_status }
  it { is_expected.to respond_to :print_warning }
  it { is_expected.to respond_to :privileged? }
  it { is_expected.to respond_to :rank }
  it { is_expected.to respond_to :rank_to_h }
  it { is_expected.to respond_to :rank_to_s }
  it { is_expected.to respond_to :refname }
  it { is_expected.to respond_to :register_parent }
  it { is_expected.to respond_to :replicant }
  it { is_expected.to respond_to :share_datastore }
  it { is_expected.to respond_to :shortname }
  it { is_expected.to respond_to :support_ipv6? }
  it { is_expected.to respond_to :target_host }
  it { is_expected.to respond_to :target_port }
  it { is_expected.to respond_to :type }
  it { is_expected.to respond_to :validate }
  it { is_expected.to respond_to :vprint_debug }
  it { is_expected.to respond_to :vprint_error }
  it { is_expected.to respond_to :vprint_good }
  it { is_expected.to respond_to :vprint_line }
  it { is_expected.to respond_to :vprint_status }
  it { is_expected.to respond_to :vprint_warning }
  it { is_expected.to respond_to :workspace }

  [
    :deregister_options,
    :derived_implementor?,
    :generate_uuid,
    :info_fixups,
    :init_compat,
    :merge_check_key,
    :merge_info,
    :merge_info_advanced_options,
    :merge_info_alias,
    :merge_info_description,
    :merge_info_evasion_options,
    :merge_info_name,
    :merge_info_options,
    :merge_info_string,
    :merge_info_version,
    :register_advanced_options,
    :register_evasion_options,
    :register_options,
    :set_defaults,
    :update_info,

  ].each do |sym|
    it "should respond to protected method #{sym}" do
      expect { subject.respond_to?(sym, true) }.to be_truthy
    end
  end

  context 'CONSTANTS' do
    context 'UpdateableOptions' do
      subject(:updateable_options) {
        described_class::UpdateableOptions
      }

      it { is_expected.to match_array(%w{Name Description Alias PayloadCompat})}
    end
  end

  context 'class' do
    subject {
      described_class
    }

    it { is_expected.to respond_to :cached? }
    it { is_expected.to respond_to :fullname }
    it { is_expected.to respond_to :is_usable }
    it { is_expected.to respond_to :rank }
    it { is_expected.to respond_to :rank_to_h }
    it { is_expected.to respond_to :rank_to_s }
    it { is_expected.to respond_to :shortname }
    it { is_expected.to respond_to :type }
  end

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
      all_module_types = Msf::MODULE_TYPES
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
