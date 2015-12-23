RSpec.describe 'msftidy utility' do
  let(:msftidy) { File.expand_path('tools/dev/msftidy.rb') }

  it "shows Usage if invalid arguments are provided" do
    expect { system(msftidy) }.to output(/Usage/).to_stderr_from_any_process
  end

  context "with a tidy auxiliary module" do
    let(:auxiliary_tidy) { File.expand_path('modules/auxiliary/auxiliary_tidy.rb', FILE_FIXTURES_PATH) }

    it "outputs nothing" do
      expect { system("#{msftidy} #{auxiliary_tidy}") }.to_not output.to_stdout_from_any_process
    end
  end

  context "with an untidy auxiliary module" do
    let(:auxiliary_untidy) { File.expand_path('modules/auxiliary/auxiliary_untidy.rb', FILE_FIXTURES_PATH) }

    it "outputs expected errors and warnings" do
      expect { system("#{msftidy} #{auxiliary_untidy}") }.to \
        output(/ERROR.*Invalid super class for auxiliary module/).to_stdout_from_any_process
    end
  end

  context "with a tidy payload module" do
    let(:payload_tidy) { File.expand_path('modules/payloads/payload_tidy.rb', FILE_FIXTURES_PATH) }

    it "outputs nothing" do
      expect { system("#{msftidy} #{payload_tidy}") }.to_not output.to_stdout_from_any_process
    end
  end
end
