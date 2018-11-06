RSpec::Matchers.define :be_in_charset do |charset|
  match do |string|
    string.chars.all? { |c| charset.include?(c) }
  end
end
