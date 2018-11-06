
RSpec::Matchers.define :eq_bytes do |expected|
  match do |actual|
    expected.force_encoding("ASCII-8BIT") == actual.force_encoding("ASCII-8BIT")
  end
end