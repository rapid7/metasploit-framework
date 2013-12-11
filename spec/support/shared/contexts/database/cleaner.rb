# -*- coding:binary -*-

shared_context 'database cleaner' do |options={}|
  options.assert_valid_keys(:after)

  scope = options.fetch(:after, :each)

  #
  # Callbacks
  #

  # Clean up after each test/context
  after(scope) do
    DatabaseCleaner.clean
  end
end
