require 'rspec/matchers'
# Special matcher for comparing encoded strings so that
# we don't run any expectation failures through the Differ,
# which also relies on EncodedString. Instead, confirm the
# strings have the same bytes.
RSpec::Matchers.define :be_identical_string do |expected|

  if String.method_defined?(:encoding)
    match do
      expected_encoding? &&
        actual.bytes.to_a == expected.bytes.to_a
    end

    failure_message do
      "expected\n#{actual.inspect} (#{actual.encoding.name}) to be identical to\n"\
        "#{expected.inspect} (#{expected.encoding.name})\n"\
        "The exact bytes are printed below for more detail:\n"\
        "#{actual.bytes.to_a}\n"\
        "#{expected.bytes.to_a}\n"\
    end

    # Depends on chaining :with_same_encoding for it to
    # check for string encoding.
    def expected_encoding?
      if defined?(@expect_same_encoding) && @expect_same_encoding
        actual.encoding == expected.encoding
      else
        true
      end
    end
  else
    match do
      actual.split(//) == expected.split(//)
    end

    failure_message do
      "expected\n#{actual.inspect} to be identical to\n#{expected.inspect}\n"
    end
  end

  chain :with_same_encoding do
    @expect_same_encoding ||= true
  end
end
RSpec::Matchers.alias_matcher :a_string_identical_to, :be_identical_string
RSpec::Matchers.alias_matcher :be_diffed_as, :be_identical_string
