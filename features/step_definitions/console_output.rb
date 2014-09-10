Then /^the output should contain the following:$/ do |table|
  table.raw.flatten.each do |expected|
    assert_partial_output(expected, all_output)
  end
end
