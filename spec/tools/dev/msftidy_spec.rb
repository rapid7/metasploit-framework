require 'spec_helper'

load Metasploit::Framework.root.join('tools/dev/msftidy.rb').to_path

RSpec.describe Msftidy do
  context "with a tidy auxiliary module" do
    let(:auxiliary_tidy) { File.expand_path('modules/auxiliary/auxiliary_tidy.rb', FILE_FIXTURES_PATH) }
    let(:msftidy) { Msftidy.new(auxiliary_tidy) }

    before(:each) do
      msftidy.run_checks
      @msftidy_status = msftidy.status
    end

    it "returns zero (no warnings or errors)" do
      expect(@msftidy_status).to be_zero
    end
  end

  context "with an untidy auxiliary module" do
    let(:auxiliary_untidy) { File.expand_path('modules/auxiliary/auxiliary_untidy.rb', FILE_FIXTURES_PATH) }
    let(:msftidy) { Msftidy.new(auxiliary_untidy) }

    before(:each) do
      @msftidy_stdout = get_stdout { msftidy.run_checks }
    end

    it "ERRORs when invalid superclass" do
      expect(@msftidy_stdout).to match(/ERROR.*Invalid super class for auxiliary module/)
    end

    it "WARNINGs when specifying Rank" do
      expect(@msftidy_stdout).to match(/WARNING.*Rank/)
    end
  end

  context "with a tidy payload module" do
    let(:payload_tidy) { File.expand_path('modules/payloads/payload_tidy.rb', FILE_FIXTURES_PATH) }
    let(:msftidy) { Msftidy.new(payload_tidy) }

    before(:each) do
      msftidy.run_checks
      @msftidy_status = msftidy.status
    end

    it "returns zero (no warnings or errors)" do
      expect(@msftidy_status).to be_zero
    end
  end
end
