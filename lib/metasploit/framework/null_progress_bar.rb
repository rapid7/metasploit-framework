# Progress bar used when one is not specified to methods that use progress bars.
class Metasploit::Framework::NullProgressBar < MetasploitDataModels::NullProgressBar
  # Sets title displayed in front of progress bar, but is ignored because this a NullObject
  #
  # @param title [String]
  # @return [void]
  def title=(title)

  end
end
