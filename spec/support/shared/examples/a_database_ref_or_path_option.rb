# -*- coding:binary -*-

RSpec.shared_examples_for "a database ref or path option" do |options|
  valid_values = [
    { value: __FILE__, normalized: __FILE__ },
    { value: '~', normalized: ::File.expand_path('~') },
    { value: 'id:1', normalized: 'id:1' },
  ]
  invalid_values = [
    { value: '0.1' },
    { value: '-1' },
    { value: '65536' },
    { value: '$' },
    { value: 'id:-1' },
    { value: 'id:' },
  ]

  it_behaves_like "an option", valid_values, invalid_values, options.fetch(:expected_type)
end

