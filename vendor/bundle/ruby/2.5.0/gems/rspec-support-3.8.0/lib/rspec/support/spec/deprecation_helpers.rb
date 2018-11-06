module RSpecHelpers
  def expect_no_deprecation
    expect(RSpec.configuration.reporter).not_to receive(:deprecation)
  end

  def expect_deprecation_with_call_site(file, line, snippet=//)
    expect(RSpec.configuration.reporter).to receive(:deprecation) do |options|
      expect(options[:call_site]).to include([file, line].join(':'))
      expect(options[:deprecated]).to match(snippet)
    end
  end

  def expect_deprecation_without_call_site(snippet=//)
    expect(RSpec.configuration.reporter).to receive(:deprecation) do |options|
      expect(options[:call_site]).to eq nil
      expect(options[:deprecated]).to match(snippet)
    end
  end

  def expect_warn_deprecation_with_call_site(file, line, snippet=//)
    expect(RSpec.configuration.reporter).to receive(:deprecation) do |options|
      message = options[:message]
      expect(message).to match(snippet)
      expect(message).to include([file, line].join(':'))
    end
  end

  def expect_warn_deprecation(snippet=//)
    expect(RSpec.configuration.reporter).to receive(:deprecation) do |options|
      message = options[:message]
      expect(message).to match(snippet)
    end
  end

  def allow_deprecation
    allow(RSpec.configuration.reporter).to receive(:deprecation)
  end

  def expect_no_deprecations
    expect(RSpec.configuration.reporter).not_to receive(:deprecation)
  end

  def expect_warning_without_call_site(expected=//)
    expect(::Kernel).to receive(:warn) do |message|
      expect(message).to match expected
      expect(message).to_not match(/Called from/)
    end
  end

  def expect_warning_with_call_site(file, line, expected=//)
    expect(::Kernel).to receive(:warn) do |message|
      expect(message).to match expected
      expect(message).to match(/Called from #{file}:#{line}/)
    end
  end

  def expect_no_warnings
    expect(::Kernel).not_to receive(:warn)
  end

  def allow_warning
    allow(::Kernel).to receive(:warn)
  end
end
