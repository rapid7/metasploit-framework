RSpec::Matchers.define :match_table do |expected|
  diffable

  match do |actual|
    @actual = actual.to_s.strip
    @expected = expected.to_s.strip

    @actual == @expected
  end

  failure_message do |actual|
    <<~MSG
      Expected:
      #{with_whitespace_highlighted(expected.to_s.strip)}
      Received:
      #{with_whitespace_highlighted(actual.to_s.strip)}
      Raw Result:
      #{actual}
    MSG
  end

  def with_whitespace_highlighted(string)
    string.lines.map { |line| "'#{line.gsub("\n", '')}'" }.join("\n")
  end
end
