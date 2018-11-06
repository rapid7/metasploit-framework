# frozen_string_literal: true
# Helper methods to parse @attr_* tags on a class.
#
# @deprecated The use of +@attr+ tags are deprecated since 0.8.0 in favour of
#   the +@!attribute+ directive. This module should not be relied on.
# @since 0.5.6
module YARD::Handlers::Ruby::StructHandlerMethods
  include YARD::CodeObjects

  # Extracts the user's defined @member tag for a given class and its member. Returns
  # nil if the user did not define a @member tag for this struct entry.
  #
  # @param [ClassObject] klass the class whose tags we're searching
  # @param [String] member the name of the struct member we need
  # @param [Symbol] type reader method, or writer method?
  # @return [Tags::Tag, nil] the tag matching the request, or nil if not found
  def member_tag_for_member(klass, member, type = :read)
    specific_tag = type == :read ? :attr_reader : :attr_writer
    (klass.tags(specific_tag) + klass.tags(:attr)).find {|tag| tag.name == member }
  end

  # Retrieves all members defined in @attr* tags
  #
  # @param [ClassObject] klass the class with the attributes
  # @return [Array<String>] the list of members defined as attributes on the class
  def members_from_tags(klass)
    tags = klass.tags(:attr) + klass.tags(:attr_reader) + klass.tags(:attr_writer)
    tags.map(&:name).uniq
  end

  # Determines whether to create an attribute method based on the class's
  # tags.
  #
  # @param [ClassObject] klass the class whose tags we're searching
  # @param [String] member the name of the struct member we need
  # @param [Symbol] type (:read) reader method, or writer method?
  # @return [Boolean] should the attribute be created?
  def create_member_method?(klass, member, type = :read)
    return true if (klass.tags(:attr) + klass.tags(:attr_reader) + klass.tags(:attr_writer)).empty?
    return true if member_tag_for_member(klass, member, type)
    return !member_tag_for_member(klass, member, :write) if type == :read
    !member_tag_for_member(klass, member, :read)
  end

  # Gets the return type for the member in a nicely formatted string. Used
  # to be injected into auto-generated docstrings.
  #
  # @param [Tags::Tag] member_tag the tag object to check for types
  # @return [String] the user-declared type of the struct member, or [Object] if
  #   the user did not define a type for this member.
  def return_type_from_tag(member_tag)
    member_tag && member_tag.types ? member_tag.types : "Object"
  end

  # Creates the auto-generated docstring for the getter method of a struct's
  # member. This is used so the generated documentation will look just like that
  # of an attribute defined using attr_accessor.
  #
  # @param [ClassObject] klass the class whose members we're working with
  # @param [String] member the name of the member we're generating documentation for
  # @return [String] a docstring to be attached to the getter method for this member
  def add_reader_tags(klass, new_method, member)
    member_tag = member_tag_for_member(klass, member, :read)
    return_type = return_type_from_tag(member_tag)
    getter_doc_text = member_tag ? member_tag.text : "Returns the value of attribute #{member}"
    new_method.docstring.replace(getter_doc_text)
    new_method.add_tag YARD::Tags::Tag.new(:return, "the current value of #{member}", return_type)
  end

  # Creates the auto-generated docstring for the setter method of a struct's
  # member. This is used so the generated documentation will look just like that
  # of an attribute defined using attr_accessor.
  #
  # @param [ClassObject] klass the class whose members we're working with
  # @param [String] member the name of the member we're generating documentation for
  # @return [String] a docstring to be attached to the setter method for this member
  def add_writer_tags(klass, new_method, member)
    member_tag = member_tag_for_member(klass, member, :write)
    return_type = return_type_from_tag(member_tag)
    setter_doc_text = member_tag ? member_tag.text : "Sets the attribute #{member}"
    new_method.docstring.replace(setter_doc_text)
    new_method.add_tag YARD::Tags::Tag.new(:param, "the value to set the attribute #{member} to.", return_type, "value")
    new_method.add_tag YARD::Tags::Tag.new(:return, "the newly set value", return_type)
  end

  # Creates and registers a class object with the given name and superclass name.
  # Returns it for further use.
  #
  # @param [String] classname the name of the class
  # @param [String] superclass the name of the superclass
  # @return [ClassObject] the class object for further processing/method attaching
  def create_class(classname, superclass)
    register ClassObject.new(namespace, classname) do |o|
      o.superclass = superclass if superclass
      o.superclass.type = :class if o.superclass.is_a?(Proxy)
    end
  end

  # Creates the setter (writer) method and attaches it to the class as an attribute.
  # Also sets up the docstring to prettify the documentation output.
  #
  # @param [ClassObject] klass the class to attach the method to
  # @param [String] member the name of the member we're generating a method for
  def create_writer(klass, member)
    # We want to convert these members into attributes just like
    # as if they were declared using attr_accessor.
    new_meth = register MethodObject.new(klass, "#{member}=", :instance) do |o|
      o.parameters = [['value', nil]]
      o.signature ||= "def #{member}=(value)"
      o.source ||= "#{o.signature}\n  @#{member} = value\nend"
    end
    add_writer_tags(klass, new_meth, member)
    klass.attributes[:instance][member][:write] = new_meth
  end

  # Creates the getter (reader) method and attaches it to the class as an attribute.
  # Also sets up the docstring to prettify the documentation output.
  #
  # @param [ClassObject] klass the class to attach the method to
  # @param [String] member the name of the member we're generating a method for
  def create_reader(klass, member)
    new_meth = register MethodObject.new(klass, member, :instance) do |o|
      o.signature ||= "def #{member}"
      o.source ||= "#{o.signature}\n  @#{member}\nend"
    end
    add_reader_tags(klass, new_meth, member)
    klass.attributes[:instance][member][:read] = new_meth
  end

  # Creates the given member methods and attaches them to the given ClassObject.
  #
  # @param [ClassObject] klass the class to generate attributes for
  # @param [Array<String>] members a list of member names
  def create_attributes(klass, members)
    # For each parameter, add reader and writers
    members.each do |member|
      next if klass.attributes[:instance][member]
      klass.attributes[:instance][member] = SymbolHash[:read => nil, :write => nil]
      create_writer klass, member if create_member_method?(klass, member, :write)
      create_reader klass, member if create_member_method?(klass, member, :read)
    end
  end
end
