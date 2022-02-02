RSpec.shared_examples_for "hash with insensitive keys" do
  it "should store with insensitive key" do
    subject["asdf"] = "foo"
    subject["ASDF"] = "bar"

    expect(subject["asdf"]).to eq "bar"
    expect(subject["ASDF"]).to eq "bar"
  end
  it "should fetch with insensitive key" do
    subject["foo"] = "bar"

    expect(subject["foo"]).to eq "bar"
    expect(subject["Foo"]).to eq "bar"
    expect(subject["FOo"]).to eq "bar"
    expect(subject["FOO"]).to eq "bar"
    expect(subject["fOO"]).to eq "bar"
    expect(subject["fOo"]).to eq "bar"
    expect(subject["FOo"]).to eq "bar"
    expect(subject["Foo"]).to eq "bar"
  end
end
