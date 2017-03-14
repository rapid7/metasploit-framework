module Msf::Module::Author
  #
  # Attributes
  #

  # @!attribute author
  #   The array of zero or more authors.
  attr_reader   :author

  #
  # Instance Methods
  #

  #
  # Return a comma separated list of author for this module.
  #
  def author_to_s
    author.collect { |author| author.to_s }.join(", ")
  end

  #
  # Enumerate each author.
  #
  def each_author(&block)
    author.each(&block)
  end

  protected

  #
  # Attributes
  #

  # @!attribute [w] author
  attr_writer :author
end
