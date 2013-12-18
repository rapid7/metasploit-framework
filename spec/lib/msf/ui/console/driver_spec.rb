require 'spec_helper'

describe Msf::Ui::Console::Driver do
  include_context 'Msf::Simple::Framework'

  subject(:driver) do
    described_class.new(
        prompt,
        prompt_char,
        opts
    )
  end

  let(:prompt) do
    described_class::DEFAULT_PROMPT
  end

  let(:prompt_char) do
    described_class::DEFAULT_PROMPT_CHAR
  end

  let(:opts) do
    {
        # turn off command pass through so tests don't have to worry about invoking system commands during tests
        'AllowCommandPassthru' => false,
        # disable banner because cmd_banner is not implemented
        'DisableBanner' => true,
        'Framework' => framework,
        # database already initialized by spec_helper
        'SkipDatabaseInit' => true
    }
  end

  it_should_behave_like 'Rex::Ui::Text::DispatcherShell' do
    let(:dispatcher_shell) do
      driver
    end
  end
end