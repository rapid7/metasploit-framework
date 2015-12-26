RSpec.shared_context 'Msf::UIDriver' do
  let(:driver) do
    double(
      'Driver',
      :framework => framework
    ).tap { |driver|
      allow(driver).to receive(:on_command_proc=).with(kind_of(Proc))
      allow(driver).to receive(:print_line).with(kind_of(String)) do |string|
        @output ||= []
        @output.concat string.split("\n")
      end
<<<<<<< HEAD
      allow(driver).to receive(:print_status).with(kind_of(String)) do |string|
        @output ||= []
        @output.concat string.split("\n")
      end
      allow(driver).to receive(:print_error).with(kind_of(String)) do |string|
=======
      driver.stub(:print_status).with(kind_of(String)) do |string|
        @output ||= []
        @output.concat string.split("\n")
      end
      driver.stub(:print_status).with(kind_of(String)) do |string|
        @output ||= []
        @output.concat string.split("\n")
      end
      driver.stub(:print_error).with(kind_of(String)) do |string|
>>>>>>> origin/4.11.2_release_pre-rails4
        @error ||= []
        @error.concat string.split("\n")
      end
    }
  end
end
