# frozen_string_literal: true

require 'rubocop/cop/lint/datastore_srvhost_usage'
require 'rubocop/rspec/support'

RSpec.describe RuboCop::Cop::Lint::DatastoreSrvhostUsage, :config do
  subject(:cop) { described_class.new(config) }

  let(:config) { RuboCop::Config.new }

  it 'corrects datastore[\'SRVHOST\'] with single quotes' do
    expect_offense(<<~RUBY)
      datastore['SRVHOST']
      ^^^^^^^^^^^^^^^^^^^^ Lint/DatastoreSrvhostUsage: Use the `srvhost` method instead of directly accessing `datastore['SRVHOST']`.
    RUBY

    expect_correction(<<~RUBY)
      srvhost
    RUBY
  end

  it 'corrects datastore["SRVHOST"] with double quotes' do
    expect_offense(<<~RUBY)
      datastore["SRVHOST"]
      ^^^^^^^^^^^^^^^^^^^^ Lint/DatastoreSrvhostUsage: Use the `srvhost` method instead of directly accessing `datastore['SRVHOST']`.
    RUBY

    expect_correction(<<~RUBY)
      srvhost
    RUBY
  end

  it 'corrects datastore[\'SRVHOST\'] in assignments' do
    expect_offense(<<~RUBY)
      host = datastore['SRVHOST']
             ^^^^^^^^^^^^^^^^^^^^ Lint/DatastoreSrvhostUsage: Use the `srvhost` method instead of directly accessing `datastore['SRVHOST']`.
    RUBY

    expect_correction(<<~RUBY)
      host = srvhost
    RUBY
  end

  it 'corrects datastore["SRVHOST"] in comparisons' do
    expect_offense(<<~RUBY)
      if datastore["SRVHOST"] == '0.0.0.0'
         ^^^^^^^^^^^^^^^^^^^^ Lint/DatastoreSrvhostUsage: Use the `srvhost` method instead of directly accessing `datastore['SRVHOST']`.
        do_something
      end
    RUBY

    expect_correction(<<~RUBY)
      if srvhost == '0.0.0.0'
        do_something
      end
    RUBY
  end

  it 'corrects datastore[\'SRVHOST\'] in method calls' do
    expect_offense(<<~RUBY)
      bind(datastore['SRVHOST'], port)
           ^^^^^^^^^^^^^^^^^^^^ Lint/DatastoreSrvhostUsage: Use the `srvhost` method instead of directly accessing `datastore['SRVHOST']`.
    RUBY

    expect_correction(<<~RUBY)
      bind(srvhost, port)
    RUBY
  end

  it 'does not flag other datastore accesses' do
    expect_no_offenses(<<~RUBY)
      datastore['SRVPORT']
    RUBY
  end

  it 'does not flag srvhost method calls' do
    expect_no_offenses(<<~RUBY)
      host = srvhost
    RUBY
  end

  it 'does not flag other variables named datastore' do
    expect_no_offenses(<<~RUBY)
      my_datastore['SRVHOST']
    RUBY
  end
end
