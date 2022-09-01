require 'spec_helper'

require Metasploit::Framework.root.join('tools/dev/msftidy.rb').to_path

RSpec.describe RuboCopRunner do
  # Metasploit globally sets `::Encoding.default_internal`, which
  # breaks reading Rubocop's ability to load its default config file
  # as UTF-8.
  #
  # Note that this is a test only issue, as msftidy runs in its own
  # Ruby process and doesn't load Metasploit which causes this issue
  def patch_io_read_encoding
    original_read = IO.method(:read)
    allow(IO).to receive(:read) do |absolute_path, **kwargs|
      original_read.call(absolute_path, **kwargs.merge(encoding: ::Encoding.default_internal))
    end
  end

  before(:each) do
    patch_io_read_encoding
  end

  context 'with a tidy module' do
    let(:file) { File.expand_path('modules/auxiliary/auxiliary_rubocopped.rb', FILE_FIXTURES_PATH) }

    before(:each) do
      allow(subject).to receive(:requires_rubocop?).and_return(true)
      @stdout = get_stdout do
        @status = subject.run(file)
      end
    end

    it 'returns zero (no warnings or errors)' do
      expect(@status).to be_zero
    end

    it 'contains no warnings' do
      expect(@stdout).to match 'no offenses detected'
    end
  end

  context 'with an untidy tidy module' do
    let(:file) { File.expand_path('modules/exploits/existing_auto_target.rb', FILE_FIXTURES_PATH) }

    before(:each) do
      allow(subject).to receive(:requires_rubocop?).and_return(true)
      @stdout = get_stdout do
        @status = subject.run(file)
      end
    end

    it 'returns zero (no warnings or errors)' do
      expect(@status).to_not be_zero
    end

    it 'contains no warnings' do
      expect(@stdout).to match 'Rubocop failed'
    end
  end

  context 'with an untidy module that is marked as too old for requiring linting' do
    let(:file) { File.expand_path('modules/exploits/existing_auto_target.rb', FILE_FIXTURES_PATH) }

    before(:each) do
      allow(subject).to receive(:requires_rubocop?).and_return(false)
      @stdout = get_stdout do
        @status = subject.run(file)
      end
    end

    it 'returns zero (no warnings or errors)' do
      expect(@status).to be_zero
    end

    it 'contains no warnings' do
      expect(@stdout).to be_empty
    end
  end
end
