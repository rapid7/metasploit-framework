RSpec.shared_context 'Msf::UIDriver' do
  let(:driver) do
    instance = double('Driver', framework: framework)
    allow(instance).to receive(:on_command_proc=).with(kind_of(Proc))
    capture_logging(instance)
    instance
  end

  let(:driver_input) do
    double(Rex::Ui::Text::Input)
  end

  let(:driver_output) do
    instance = double(
      Rex::Ui::Text::Output,
      prompting?: false
    )

    capture_logging(instance)
    instance
  end

  def capture_logging(target)
    append_output = proc do |string|
      lines = string.split("\n")
      @output ||= []
      @output.concat(lines)
      @combined_output ||= []
      @combined_output.concat(lines)
    end
    append_error = proc do |string|
      lines = string.split("\n")
      @error ||= []
      @error.concat(lines)
      @combined_output ||= []
      @combined_output.concat(lines)
    end

    allow(target).to receive(:print).with(kind_of(String), &append_output)
    allow(target).to receive(:print_line).with(kind_of(String), &append_output)
    allow(target).to receive(:print_status).with(kind_of(String), &append_output)
    allow(target).to receive(:print_warning).with(kind_of(String), &append_error)
    allow(target).to receive(:print_error).with(kind_of(String), &append_error)
    allow(target).to receive(:print_bad).with(kind_of(String), &append_error)
  end
end
