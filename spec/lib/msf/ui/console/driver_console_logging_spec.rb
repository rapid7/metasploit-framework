# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Ui::Console::Driver do
  let(:driver) { described_class.allocate }
  let(:output) { instance_double(Rex::Ui::Text::Output::Stdio, print_warning: nil) }

  before do
    allow(driver).to receive(:output).and_return(output)
    driver.set_log_source('console')
  end

  it 'allows input and output to continue, warning once until the log recovers' do
    allow(driver).to receive(:rlog) do |message, _source|
      raise Errno::ENOSPC unless message == 'recovered'

      :written
    end

    expect { driver.send(:log_input, 'first failure') }.not_to raise_error
    expect { driver.send(:log_output, 'same failure') }.not_to raise_error
    expect(output).to have_received(:print_warning).with(/Could not write the console log:/).once
    expect(driver.send(:log_output, 'recovered')).to eq(:written)
    expect { driver.send(:log_input, 'another failure') }.not_to raise_error
    expect(output).to have_received(:print_warning).with(/Could not write the console log:/).twice
  end

  it 'turns off console logging when the final write and close report an I/O error' do
    allow(driver).to receive(:rlog).and_raise(Errno::ENOSPC)
    allow(Msf::Logging).to receive(:disable_log_source).with('console').and_raise(Errno::ENOSPC)
    allow(driver).to receive(:print_line)

    expect { driver.send(:handle_console_logging, 'false') }.not_to raise_error
    expect(Msf::Logging).to have_received(:disable_log_source).with('console')
    expect(driver).to have_received(:print_line).with('Console logging is now disabled.')
    expect { driver.send(:log_output, 'after disabling') }.not_to raise_error
    expect(output).to have_received(:print_warning).once

    allow(Msf::Logging).to receive(:enable_log_source).with('console')
    expect { driver.send(:handle_console_logging, 'true') }.not_to raise_error
    expect(output).to have_received(:print_warning).twice
  end

  it 'retains error propagation for other log sources' do
    driver.set_log_source('other')
    allow(driver).to receive(:rlog).with('message', 'other').and_raise(Errno::ENOSPC)

    expect { driver.send(:log_output, 'message') }.to raise_error(Errno::ENOSPC)
    expect(output).not_to have_received(:print_warning)
  end
end
