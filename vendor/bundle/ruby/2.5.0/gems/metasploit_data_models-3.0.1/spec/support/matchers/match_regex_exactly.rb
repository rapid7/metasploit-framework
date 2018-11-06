# Checks that the string matches the
RSpec::Matchers.define :match_string_exactly do |string|
  failure_message do |regexp|
    match = regexp.match(string)

    failure_message = "expected #{regexp} to match #{string}"

    if match
      failure_message << ', but'

      unless match.pre_match.empty?
        failure_message << " pre-match is #{match.pre_match}"
      end

      unless match.post_match.empty?
        failure_message << " post-match is #{match.post_match}"
      end
    end

    failure_message
  end

  match do |regexp|
    match = regexp.match(string)

    match && match.pre_match.empty? && match.post_match.empty?
  end
end