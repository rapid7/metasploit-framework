%w[
  any_instance/chain
  any_instance/error_generator
  any_instance/stub_chain
  any_instance/stub_chain_chain
  any_instance/expect_chain_chain
  any_instance/expectation_chain
  any_instance/message_chains
  any_instance/recorder
  any_instance/proxy
].each { |f| RSpec::Support.require_rspec_mocks(f) }
