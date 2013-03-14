$DEBUG_RDOC = nil

# :main: README.rdoc

##
# RDoc is a Ruby documentation system which contains RDoc::RDoc for generating
# documentation, RDoc::RI for interactive documentation and RDoc::Markup for
# text markup.
#
# RDoc::RDoc produces documentation for Ruby source files.  It works similarly
# to JavaDoc, parsing the source and extracting the definition for classes,
# modules, methods, includes and requires.  It associates these with optional
# documentation contained in an immediately preceding comment block then
# renders the result using an output formatter.
#
# RDoc::Markup that converts plain text into various output formats.  The
# markup library is used to interpret the comment blocks that RDoc uses to
# document methods, classes, and so on.
#
# RDoc::RI implements the +ri+ command-line tool which displays on-line
# documentation for ruby classes, methods, etc.  +ri+ features several output
# formats and an interactive mode (<tt>ri -i</tt>).  See <tt>ri --help</tt>
# for further details.
#
# == Roadmap
#
# * If you think you found a bug in RDoc see DEVELOPERS@Bugs
# * If you want to use RDoc to create documentation for your Ruby source files,
#   see RDoc::Markup and refer to <tt>rdoc --help</tt> for command line
#   usage.
# * If you want to store rdoc configuration in your gem see
#   RDoc::Options@Saved+Options
# * If you want to write documentation for Ruby files see RDoc::Parser::Ruby
# * If you want to write documentation for extensions written in C see
#   RDoc::Parser::C
# * If you want to generate documentation using <tt>rake</tt> see RDoc::Task.
# * If you want to drive RDoc programmatically, see RDoc::RDoc.
# * If you want to use the library to format text blocks into HTML or other
#   formats, look at RDoc::Markup.
# * If you want to make an RDoc plugin such as a generator or directive
#   handler see RDoc::RDoc.
# * If you want to write your own output generator see RDoc::Generator.
# * If you want an overview of how RDoc works see DEVELOPERS
#
# == Summary
#
# Once installed, you can create documentation using the +rdoc+ command
#
#   % rdoc [options] [names...]
#
# For an up-to-date option summary, type
#
#   % rdoc --help
#
# A typical use might be to generate documentation for a package of Ruby
# source (such as RDoc itself).
#
#   % rdoc
#
# This command generates documentation for all the Ruby and C source
# files in and below the current directory.  These will be stored in a
# documentation tree starting in the subdirectory +doc+.
#
# You can make this slightly more useful for your readers by having the
# index page contain the documentation for the primary file.  In our
# case, we could type
#
#   % rdoc --main README.rdoc
#
# You'll find information on the various formatting tricks you can use
# in comment blocks in the documentation this generates.
#
# RDoc uses file extensions to determine how to process each file.  File names
# ending +.rb+ and +.rbw+ are assumed to be Ruby source.  Files
# ending +.c+ are parsed as C files.  All other files are assumed to
# contain just Markup-style markup (with or without leading '#' comment
# markers).  If directory names are passed to RDoc, they are scanned
# recursively for C and Ruby source files only.
#
# == Other stuff
#
# RDoc is currently being maintained by Eric Hodel <drbrain@segment7.net>.
#
# Dave Thomas <dave@pragmaticprogrammer.com> is the original author of RDoc.
#
# == Credits
#
# * The Ruby parser in rdoc/parse.rb is based heavily on the outstanding
#   work of Keiju ISHITSUKA of Nippon Rational Inc, who produced the Ruby
#   parser for irb and the rtags package.

module RDoc

  ##
  # Exception thrown by any rdoc error.

  class Error < RuntimeError; end

  def self.const_missing const_name # :nodoc:
    if const_name.to_s == 'RDocError' then
      warn "RDoc::RDocError is deprecated and will be removed in RDoc 4"
      return Error
    end

    super
  end

  ##
  # RDoc version you are using

  VERSION = '3.12'

  ##
  # Method visibilities

  VISIBILITIES = [:public, :protected, :private]

  ##
  # Name of the dotfile that contains the description of files to be processed
  # in the current directory

  DOT_DOC_FILENAME = ".document"

  ##
  # General RDoc modifiers

  GENERAL_MODIFIERS = %w[nodoc].freeze

  ##
  # RDoc modifiers for classes

  CLASS_MODIFIERS = GENERAL_MODIFIERS

  ##
  # RDoc modifiers for attributes

  ATTR_MODIFIERS = GENERAL_MODIFIERS

  ##
  # RDoc modifiers for constants

  CONSTANT_MODIFIERS = GENERAL_MODIFIERS

  ##
  # RDoc modifiers for methods

  METHOD_MODIFIERS = GENERAL_MODIFIERS +
    %w[arg args yield yields notnew not-new not_new doc]

  ##
  # Loads the best available YAML library.

  def self.load_yaml
    begin
      gem 'psych'
    rescue Gem::LoadError
    end

    begin
      require 'psych'
    rescue ::LoadError
    ensure
      require 'yaml'
    end
  end

  autoload :RDoc,           'rdoc/rdoc'

  autoload :TestCase,       'rdoc/test_case'

  autoload :CrossReference, 'rdoc/cross_reference'
  autoload :ERBIO,          'rdoc/erbio'
  autoload :Encoding,       'rdoc/encoding'
  autoload :Generator,      'rdoc/generator'
  autoload :Options,        'rdoc/options'
  autoload :Parser,         'rdoc/parser'
  autoload :RI,             'rdoc/ri'
  autoload :Stats,          'rdoc/stats'
  autoload :Task,           'rdoc/task'
  autoload :Text,           'rdoc/text'

  autoload :Markup,         'rdoc/markup'
  autoload :RD,             'rdoc/rd'
  autoload :TomDoc,         'rdoc/tom_doc'

  autoload :KNOWN_CLASSES,  'rdoc/known_classes'

  autoload :RubyLex,        'rdoc/ruby_lex'
  autoload :RubyToken,      'rdoc/ruby_token'
  autoload :TokenStream,    'rdoc/token_stream'

  autoload :Comment,        'rdoc/comment'

  # code objects
  #
  # We represent the various high-level code constructs that appear in Ruby
  # programs: classes, modules, methods, and so on.
  autoload :CodeObject,     'rdoc/code_object'

  autoload :Context,        'rdoc/context'
  autoload :TopLevel,       'rdoc/top_level'

  autoload :AnonClass,      'rdoc/anon_class'
  autoload :ClassModule,    'rdoc/class_module'
  autoload :NormalClass,    'rdoc/normal_class'
  autoload :NormalModule,   'rdoc/normal_module'
  autoload :SingleClass,    'rdoc/single_class'

  autoload :Alias,          'rdoc/alias'
  autoload :AnyMethod,      'rdoc/any_method'
  autoload :MethodAttr,     'rdoc/method_attr'
  autoload :GhostMethod,    'rdoc/ghost_method'
  autoload :MetaMethod,     'rdoc/meta_method'
  autoload :Attr,           'rdoc/attr'

  autoload :Constant,       'rdoc/constant'
  autoload :Include,        'rdoc/include'
  autoload :Require,        'rdoc/require'

end

