RSpec::Matchers.define :have_body do |expected|
  match do |response|
    response.body.should == expected
  end

  description do
    "have body #{expected.inspect}"
  end
end
