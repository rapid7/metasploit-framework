class Metasploit::Framework::Thread::Manager::AlreadyRegistered < Metasploit::Framework::Error
  #
  # Attributes
  #

  # @!attribute [r] metasploit_framework_thread
  #   The prior registration for the `Thread`.
  #
  #   @return [Metasploit::Framework::Thread]
  attr_reader :metasploit_framework_thread

  #
  # Methods
  #

  # @param metasploit_framework_thread [Metasploit::Framework::Thread] The pre-existing registration for the current
  #   `Thread`.
  def initialize(metasploit_framework_thread)
    @metasploit_framework_thread = metasploit_framework_thread

    super(
        "Current thread already registered to a Metasploit::Framework::Thread::Manager " \
        "with #{metasploit_framework_thread.inspect}"
    )
  end
end