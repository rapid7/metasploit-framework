# spec_helper for running Meterpreter acceptance tests
require 'allure_config'
require 'spec_helper'
require 'test_prof/recipes/rspec/let_it_be'

acceptance_support_glob = File.expand_path(File.join(File.dirname(__FILE__), 'support', 'acceptance', '**', '*.rb'))
shared_contexts_glob = File.expand_path(File.join(File.dirname(__FILE__), 'support', 'shared', 'contexts', '**', '*.rb'))
Dir[acceptance_support_glob, shared_contexts_glob].each do |f|
  require f
end

class MetasploitTransactionAdapter
  # before_all adapters must implement two methods:
  # - begin_transaction
  # - rollback_transaction
  def begin_transaction
    # noop
  end

  def rollback_transaction
    # noop
  end
end

RSpec.configure do |config|
  TestProf::BeforeAll.adapter = MetasploitTransactionAdapter.new
end
