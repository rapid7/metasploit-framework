# Methods dealing with the author(s) of a module, not be be confused with {Msf::Module::Author}, which is the `Class`
# used to present (author, email) tuples in memory.
module Msf::Module::Authors
  require 'msf/core/module/author'

  # @deprecated Use {#authors} instead.
  # @return (see @authors)
  def author
    ActiveSupport::Deprecation.warn "#{self}##{__method__} is deprecated. Use #{self}#authors instead"
    authors
  end

  # @deprecated Use {#authors_to_s} instead.
  # @return (see #authors_to_s)
  def author_to_s
    ActiveSupport::Deprecation.warn "#{self}##{__method__} is deprecated. Use #{self}#authors_to_s instead"
  end

  # The authors (including their {Msf::Module::Author#name name} and {Msf::Module::Author#email}) of this module.
  #
  # @return [Array<Msf::Module::Author>]
  def authors
    @authors ||= Msf::Module::Author.transform(module_info['Author'])
  end

  # Comma separated list of author for this module.
  #
  # @return [String]
  def authors_to_s
    formatted_authors = authors.map(&:to_s)
    formatted_authors.join(', ')
  end

  # Enumerate each author.
  #
  # @yield [author]
  # @yieldparam author [Msf::Module::Author]
  # @yieldreturn [void]
  # @return [void]
  def each_author(&block)
    authors.each(&block)
  end
end