describe MethodSource::CodeHelpers do
  before do
    @tester = Object.new.extend(MethodSource::CodeHelpers)
  end

  [
    ["p = '", "'"],
    ["def", "a", "(); end"],
    ["p = <<FOO", "lots", "and", "lots of", "foo", "FOO"],
    ["[", ":lets,", "'list',", "[/nested/", "], things ]"],
    ["abc =~ /hello", "/"],
    ["issue = %W/", "343/"],
    ["pouts(<<HI, 'foo", "bar", "HI", "baz')"],
    ["=begin", "no-one uses this syntax anymore...", "=end"],
    ["puts 1, 2,", "3"],
    ["puts 'hello'\\", "'world'"]
  ].each do |lines|
    it "should not raise an error on broken lines: #{lines.join("\\n")}" do
      1.upto(lines.size - 1) do |i|
        @tester.complete_expression?(lines[0...i].join("\n") + "\n").should == false
      end
      @tester.complete_expression?(lines.join("\n")).should == true
    end
  end

  [
    ["end"],
    ["puts )("],
    ["1 1"],
    ["puts :"]
  ] + (RbConfig::CONFIG['ruby_install_name'] == 'rbx' ? [] : [
    ["def", "method(1"], # in this case the syntax error is "expecting ')'".
    ["o = Object.new.tap{ def o.render;","'MEH'", "}"] # in this case the syntax error is "expecting keyword_end".
  ]).compact.each do |foo|
    it "should raise an error on invalid syntax like #{foo.inspect}" do
      lambda{
        @tester.complete_expression?(foo.join("\n"))
      }.should.raise(SyntaxError)
    end
  end
end
