# Progress Bar used in specs so that module cache contruction continues to output to stdout on a regular basis to
# prevent travis-ci from thinking the build has hung.  Prints 'a' whenever {#increment} is called.
class Metasploit::Framework::Spec::ProgressBar
  #
  # Attributes
  #

  # @!attribute [rw] [progress]
  #   Progress towards {#total}.
  #
  #   @return [Integer]
  attr_writer :progress

  # @!attribute [rw] title
  #   What is being measured by this progress bar
  #
  #   @return [String]
  attr_accessor :title

  # @!attribute [rw] total
  #   The total number of steps in this progress bar
  #
  #   @return [Integer]
  attr_accessor :total

  #
  # Methods
  #

  def increment
    self.progress += 1

    $stdout.write 'a'
  end

  def progress
    @progress ||= 0
  end
end