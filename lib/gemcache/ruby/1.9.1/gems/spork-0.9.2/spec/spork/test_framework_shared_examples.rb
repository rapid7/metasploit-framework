shared_examples "a TestFramework" do
  describe ".default_port" do
    it "uses the DEFAULT_PORT when the environment variable is not set" do
      described_class.default_port.should == described_class::DEFAULT_PORT
    end

    it 'uses ENV["#{short_name.upcase}_DRB"] as port if present' do
      env_name = "#{described_class.short_name.upcase}_DRB"
      orig, ENV[env_name] = ENV[env_name], "9000"
      begin
        described_class.default_port.should == 9000
      ensure
        ENV[env_name] = orig
      end
    end
  end

  describe ".helper_file" do
    it "returns ::HELPER_FILE for the TestFramework" do
      described_class.helper_file.should == described_class::HELPER_FILE
    end
  end
end
