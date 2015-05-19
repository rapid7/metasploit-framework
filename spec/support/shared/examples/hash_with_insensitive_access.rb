shared_examples_for "hash with insensitive keys" do
  it "should store with insensitive key" do
    subject["asdf"] = "foo"
    subject["ASDF"] = "bar"

    subject["asdf"].should == "bar"
    subject["ASDF"].should == "bar"
  end
  it "should fetch with insensitive key" do
    subject["foo"] = "bar"

    subject["foo"].should == "bar"
    subject["Foo"].should == "bar"
    subject["FOo"].should == "bar"
    subject["FOO"].should == "bar"
    subject["fOO"].should == "bar"
    subject["fOo"].should == "bar"
    subject["FOo"].should == "bar"
    subject["Foo"].should == "bar"
  end
end
