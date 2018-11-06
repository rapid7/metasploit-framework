module Pry::Testable::Utility
  #
  # Creates a Tempfile then unlinks it after the block has yielded.
  #
  # @yieldparam [String] file
  #   The path of the temp file
  #
  # @return [void]
  #
  def temp_file(ext='.rb')
    file = Tempfile.open(['pry', ext])
    yield file
  ensure
    file.close(true) if file
  end

  def unindent(*args)
    Pry::Helpers::CommandHelpers.unindent(*args)
  end

  def inner_scope
    catch(:inner_scope) do
      yield ->{ throw(:inner_scope, self) }
    end
  end
end
