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
    unless instance_variable_defined? :@authors
      transformed_authors = Msf::Module::Author.transform(module_info['Author'])
      # transformed_authors may contain redundant entries from merging, such as two Msf::Module::Authors with the same
      # name, but different emails.
      authors_by_name = transformed_authors.group_by(&:name)

      @authors = authors_by_name.each_with_object([]) { |(name, named_authors), merged_authors|
        email_set = named_authors.each_with_object(Set.new) { |named_author, set|
          email = named_author.email

          # need to use present? because Msf::Module::Author#email may be nil or ''.
          if email.present?
            set.add email
          end
        }

        email_count = email_set.length

        # if there the author is listed more than once and with multiple emails, then it can't be decided which to
        # favor, so the developer needs to just fix the old emails in the older code.
        if email_count > 1
          raise ArgumentError,
                "#{name} has multiple email addresses for this module: #{email_set.sort.to_sentence}"
        # when there is only one author with one email, then use the email
        # when there is one author with one email and the same author without the email, favor the email
        elsif email_count == 1
          email = email_set.first
        # if the name is used one or more times, but never with an email, then have to use no email
        else
          email = nil
        end

        merged_authors << Msf::Module::Author.new(name, email)
      }
    end

    @authors
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