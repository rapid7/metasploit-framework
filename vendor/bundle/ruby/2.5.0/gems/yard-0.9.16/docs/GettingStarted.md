# @title Getting Started Guide

# Getting Started with YARD

There are a few ways which YARD can be of use to you or your project. This
document will cover the most common ways to use YARD:

* [Documenting Code with YARD](#docing)
* [Using YARD to Generate Documentation](#using)
* [Configuring YARD](#config)
* [Extending YARD](#extending)
* [Templating YARD](#templating)
* [Plugin Support](#plugins)

<a name="docing"></a>

## Documenting Code with YARD

By default, YARD is compatible with the same RDoc syntax most Ruby developers
are already familiar with. However, one of the biggest advantages of YARD is
the extended meta-data syntax, commonly known as "tags", that you can use
to express small bits of information in a structured and formal manner. While
RDoc syntax expects you to describe your method in a completely free-form
manner, YARD recommends declaring your parameters, return types, etc. with
the `@tag` syntax, which makes outputting the documentation more consistent
and easier to read. Consider the RDoc documentation for a method to_format:

    # Converts the object into textual markup given a specific `format`
    # (defaults to `:html`)
    #
    # == Parameters:
    # format::
    #   A Symbol declaring the format to convert the object to. This
    #   can be `:text` or `:html`.
    #
    # == Returns:
    # A string representing the object in a specified
    # format.
    #
    def to_format(format = :html)
      # format the object
    end

While this may seem easy enough to read and understand, it's hard for a machine
to properly pull this data back out of our documentation. Also we've tied our
markup to our content, and now our documentation becomes hard to maintain if
we decide later to change our markup style (maybe we don't want the ":" suffix
on our headers anymore).

In YARD, we would simply define our method as:

    # Converts the object into textual markup given a specific format.
    #
    # @param format [Symbol] the format type, `:text` or `:html`
    # @return [String] the object converted into the expected format.
    def to_format(format = :html)
      # format the object
    end

Using tags we can add semantic metadata to our code without worrying about
presentation. YARD will handle presentation for us when we decide to generate
documentation later.

## Which Markup Format?

YARD does not impose a specific markup. The above example uses standard RDoc
markup formatting, but YARD also supports textile and markdown via the
command-line switch or `.yardopts` file (see below). This means that you are
free to use whatever formatting you like. This guide is actually written
using markdown. YARD, however, does add a few important syntaxes that are
processed no matter which markup formatting you use, such as tag support
and inter-document linking. These syntaxes are discussed below.

## Adding Tags to Documentation

The tag syntax that YARD uses is the same @tag-style syntax you may have seen
if you've ever coded in Java, Python, PHP, Objective-C or a myriad of other
languages. The following tag adds an author tag to your class:

    # @author Loren Segal
    class MyClass
    end

To allow for large amounts of text, the @tag syntax will recognize any indented
lines following a tag as part of the tag data. For example:

    # @deprecated Use {#my_new_method} instead of this method because
    #   it uses a library that is no longer supported in Ruby 1.9.
    #   The new method accepts the same parameters.
    def mymethod
    end

### List of Tags

A list of tags can be found in {file:docs/Tags.md#taglist}

### Reference Tags

To reduce the amount of duplication in writing documentation for repetitive
code, YARD introduces "reference tags", which are not quite tags, but not
quite docstrings either. In a sense, they are tag (and docstring) modifiers.
Basically, any docstring (or tag) that begins with "(see OTHEROBJECT)" will
implicitly link the docstring or tag to the "OTHEROBJECT", copying any data
from that docstring/tag into your current object. Consider the example:

    class MyWebServer
      # Handles a request
      # @param request [Request] the request object
      # @return [String] the resulting webpage
      def get(request) "hello" end

      # (see #get)
      def post(request) "hello" end
    end

The above `#post` method takes the docstring and all tags (`param` and `return`)
of the `#get` method. When you generate HTML documentation, you will see this
duplication automatically, so you don't have to manually type it out. We can
also add our own custom docstring information below the "see" reference, and
whatever we write will be appended to the docstring:

    # (see #get)
    # @note This method may modify our application state!
    def post(request) self.state += 1; "hello" end

Here we added another tag, but we could have also added plain text. The
text must be appended *after* the `(see ...)` statement, preferably on
a separate line.

Note that we don't have to "refer" the whole docstring. We can also link
individual tags instead. Since "get" and "post" actually have different
descriptions, a more accurate example would be to only refer our parameter
and return tags:

    class MyWebServer
      # Handles a GET request
      # @param request [Request] the request object
      # @return [String] the resulting webpage
      def get(request) "hello" end

      # Handles a POST request
      # @note This method may modify our application state!
      # @param (see #get)
      # @return (see #get)
      def post(request) self.state += 1; "hello" end
    end

The above copies all of the param and return tags from `#get`. Note that you
cannot copy individual tags of a specific type with this syntax.

## Declaring Types

Some tags also have an optional "types" field which let us declare a list of
types associated with the tag. For instance, a return tag can be declared
with or without a types field.

    # @return [String, nil] the contents of our object or nil
    #   if the object has not been filled with data.
    def validate; end

    # We don't care about the "type" here:
    # @return the object
    def to_obj; end

The list of types is in the form `[type1, type2, ...]` and is mostly free-form,
so we can also specify duck-types or constant values. For example:

    # @param argname [#to_s] any object that responds to `#to_s`
    # @param argname [true, false] only true or false

Note the latter example can be replaced by the meta-type "Boolean".
Another meta-type is "void", which stands for "no meaningful value"
and is used for return values. These meta-types are by convention
only, but are recommended.

List types can be specified in the form `CollectionClass<ElementType, ...>`.
For instance, consider the following Array that holds a set of Strings and
Symbols:

    # @param list [Array<String, Symbol>] the list of strings and symbols.

We mentioned that these type fields are "mostly" free-form. In truth, they
are defined "by convention". To view samples of common type specifications
and recommended conventions for writing type specifications, see
[http://yardoc.org/types.html](http://yardoc.org/types.html). Note that these
conventions may change every now and then, although we are working on a more
"formal" type specification proposal.

## Documenting Attributes

To document a Ruby attribute, add documentation text above the attribute
definition.

    # Controls the amplitude of the waveform.
    # @return [Numeric] the amplitude of the waveform
    attr_accessor :amplitude

As a short-hand syntax for declaring reader and writer attribute pairs,
YARD will automatically wire up the correct method types and information
by simply defining documentation in the `@return` tag. For example,
the following declaration will show the correct information for the
`waveform` attribute, both for the getter's return type and the
setter's value parameter type: 

    # @return [Numeric] the amplitude of the waveform
    attr_accessor :amplitude

In this case, the most important details for the attribute are the
object type declaration and its descriptive text.

### Documentation for a Separate Attribute Writer

Usually an attribute will get and set a value using the same syntax,
so there is no reason to have separate documentation for an attribute
writer. In the above `amplitude` case, the `Numeric` type is both used
for the getter and setter types.

Sometimes, however, you might want to have separate documentation
for the getter and setter. In this case, you would still add
the documentation text to the getter declaration (or `attr_accessor`)
and use `@overload` tags to declare the separate docstrings. For example:

    # @overload amplitude
    #   Gets the current waveform amplitude.
    #   @return [Numeric] the amplitude of the waveform
    # @overload amplitude=(value)
    #   Sets the new amplitude.
    #   @param value [Numeric] the new amplitude value
    #   @note The new amplitude will only take effect if {#restart}
    #     is called on the stream.

Note that by default, YARD exposes the reader portion of the attribute
in HTML output. If you have separate `attr_reader` and `attr_writer`
declarations, make sure to put your documentation (for both reader
and writer methods) on the reader declaration using `@overload`
tags as described above. For example:

    # @overload ...documentation here...
    attr_reader :amplitude

    # This documentation will be ignored by YARD.
    attr_writer :amplitude

## Documenting Custom DSL Methods

Application code in Ruby often makes use of DSL style metaprogrammed methods.
The most common is the `attr_accessor` method, which of course has built-in
support in YARD. However, frameworks and libraries often expose custom
methods that perform similar metaprogramming tasks, and it is often useful
to document their functionality in your application. Consider the `property`
method in a project like [DataMapper](http://datamapper.org), which creates
a typed attribute for a database model. The code might look like:

    class Post
      include DataMapper::Resource

      property :title, String
    end

As of version 0.7.0, YARD will automatically pick up on these basic methods if
you document them with a docstring. Therefore, simply adding some comments to
the code will cause it to generate documentation:

    class Post
      include DataMapper::Resource

      # @return [String] the title property of the post
      property :title, String
    end

Note that YARD uses the first argument in the method call to determine the
method name. In some cases, this would not be the method name, and you would
need to declare it manually. You can do so with the `@!method` directive:

    # @!method foo
    create_a_foo_method

The @!method directive can also accept a full method signature with parameters:

    # @!method foo(name, opts = {})
    create_a_foo_method

You can also set visibility and scope, or modify the method signature with
extra tags. The following adds documentation for a private class method:

    # @!method foo(opts = {})
    # The foo method!
    # @!scope class
    # @!visibility private
    create_a_private_foo_class_method

Finally, you can tag a method as an attribute by replacing the @!method
tag with @!attribute. The @!attribute directive allows for the flags [r], [w],
or [rw] to declare a readonly, writeonly, or readwrite attribute, respectively.

    # @!attribute [w]
    # The writeonly foo attribute!
    a_writeonly_attribute :foo

(Note that if the name can be automatically detected, you do not need to
specify it in the @!method or @!attribute directives)

However, you will notice a few drawbacks with this basic support:

1. There is a fair bit of duplication in such documentation. Specifically, we
   repeat the term String and title twice in the property example.
2. We must write a code comment for this property to show up in the documentation.
   If we do not write a comment, it is ignored.

### Macros

Fortunately YARD 0.7.0 also adds macros, a powerful way to add support for
these DSL methods on the fly without writing extra plugins. Macros allow
you to interpolate arguments from the method call inside the docstring,
reducing duplication. If we re-wrote the `property` example from above
using a macro, it might look like:

    class Post
      include DataMapper::Resource

      # @!macro dm.property
      # @return [$2] the $1 $0 of the post
      property :title, String
    end

(Note that $0 represents the method call, in this case `property`. The rest
are arguments in the method call.)

The above example is equivalent to the first version shown in the previous
section. There is also some extra benefit to using this macro, in that we
can re-apply it to any other property in our class by simply calling on
the macro. The following:

    # @!macro dm.property
    property :view_count, Integer

Would be equivalent to:

    # @return [Integer] the view_count property of the post
    property :view_count, Integer

Finally, macros can be "attached" to method calls, allowing them to be implicitly
activated every time the method call is seen in the source code of the class,
or an inheriting class. By simply adding the `[attach]` flag, the macro
becomes implicit on future calls. All of the properties below get documented
by using this snippet:

    class Post
      include DataMapper::Resource

      # @!macro [attach] dm.property
      # @return [$2] the $1 $0 of the post
      property :title, String
      property :view_count, Integer
      property :email, String
    end

You can read more about macros in the {file:docs/Tags.md Tags Overview} document.

## Customized YARD Markup

YARD supports a special syntax to link to other code objects, URLs, files,
or embed docstrings between documents. This syntax has the general form
of `{Name OptionalTitle}` (where `OptionalTitle` can have spaces, but `Name`
cannot).

### Linking Objects `{...}`

To link another "object" (class, method, module, etc.), use the format:

    {ObjectName#method OPTIONAL_TITLE}
    {Class::CONSTANT My constant's title}
    {#method_inside_current_namespace}

Without an explicit title, YARD will use the relative path to the object as
the link name. Note that you can also use relative paths inside the object
path to refer to an object inside the same namespace as your current docstring.

Note that the `@see` tag automatically links its data. You should not use
the link syntax in this tag:

    # @see #methodname   <- Correct.
    # @see {#methodname} <- Incorrect.

If you want to use a Hash, prefix the first { with "!":

   # !{ :some_key => 'value' }

### Linking URLs `{http://...}`

URLs are also linked using this `{...}` syntax:

    {http://example.com Optional Title}
    {mailto:email@example.com}

### Linking Files `{file:...}`

Files can also be linked using this same syntax but by adding the `file:`
prefix to the object name. Files refer to extra readme files you added
via the command-line. Consider the following examples:

    {file:docs/GettingStarted.md Getting Started}
    {file:mypage.html#anchor Name}

As shown, you can also add an optional `#anchor` if the page is an HTML link.

### Embedding Docstrings `{include:...}`

We saw the `(see ...)` syntax above, which allowed us to link an entire docstring
with another. Sometimes, however, we just want to copy docstring text without
tags. Using the same `{...}` syntax, but using the `include:` prefix, we can
embed a docstring (minus tags) at a specific point in the text.

    # This class is cool
    # @abstract
    class Foo; end

    # This is another class. {include:Foo} too!
    class Bar; end

The docstring for Bar becomes:

    "This is another class. This class is cool too!"

### Embedding Files `{include:file:...}`

You can embed the contents of files using `{include:file:path/to/file}`,
similar to the `{include:OBJECT}` tag above. If the file uses a specific markup
type, it will be applied and embedded as marked up text. The following
shows how the tag can be used inside of comments:

    # Here is an example of a highlighted Ruby file:
    #
    # {include:file:examples/test.rb}

### Rendering Objects `{render:...}`

Entire objects can also be rendered in place in documentation. This can be
used for guide-style documentation which does not document the entire source
tree, but instead selectively renders important classes or methods. Consider
the following documentation inside of a README file:

    !!!plain
    = igLatinPay!

    This library adds pig latin methods to the string class, allowing you
    to transform sentences into pig latin.

    {render:String#pig_latin}

    You can also un-pig-latin-ify a word or sentence:

    {render:String#de_pig_latin}

The above would render the methods in place inside the README document,
allowing you to summarize a small library in a single file.

<a name="using"></a>

## Using YARD to Generate Documentation

### `yard` Executable

YARD ships with a single executable aptly named `yard`. In addition to
generating standard documentation for your project, you would use this tool
if you wanted to:

* Document all installed gems
* Run a local documentation server
* Generate UML diagrams using [Graphviz][graphviz]
* View `ri`-style documentation
* Diff your documentation
* Analyze documentation statistics.

The following commands are available in YARD 0.6.x (see `yard help` for a
full list):

    Usage: yard <command> [options]

    Commands:
    config   Views or edits current global configuration
    diff     Returns the object diff of two gems or .yardoc files
    doc      Generates documentation
    gems     Builds YARD index for gems
    graph    Graphs class diagram using Graphviz
    help     Retrieves help for a command
    ri       A tool to view documentation in the console like `ri`
    server   Runs a local documentation server
    stats    Prints documentation statistics on a set of files

Note that `yardoc` is an alias for `yard doc`, and `yri` is an alias for
`yard ri`. These commands are maintained for backwards compatibility.

### `.yardopts` Options File

Unless your documentation is very small, you'll end up needing to run `yardoc`
with many options.  The `yardoc` tool will use the options found in this file.
It is recommended to check this in to your repository and distribute it with
your source. This file is placed at the root of your project (in the directory
you run `yardoc` from) and contains all of arguments you would otherwise pass
to the command-line tool. For instance, if you often type:

    yardoc --no-private --protected app/**/*.rb - README LEGAL COPYING

You can place the following into your `.yardopts`:

    --no-private --protected app/**/*.rb - README LEGAL COPYING

This way, you only need to type:

    yardoc

Any extra switches passed to the command-line now will be appended to your
`.yardopts` options.

Note that options for `yardoc` are discussed in the {file:README.md README},
and a full overview of the `.yardopts` file can be found in {YARD::CLI::Yardoc}.

### Documenting Extra Files

"Extra files" are extra guide style documents that help to give a brief overview
of how to use your library/framework, as well as any extra information that
might be vital for your users. The most common "extra file" is the README,
which is automatically detected by YARD if found in the root of your project
(any file starting with `README*`). You can specify extra files on the command
line (or in the `.yardopts` file) by listing them after the '-' separator:

    yardoc lib/**/*.rb ext/**/*.c - LICENSE.txt

Note that the README will automatically be picked up, so you do not need to
specify it. If you don't want to modify the default file globs, you can ignore
the first set of arguments:

    yardoc - LICENSE.txt

Below you can read about how to customize the look of these extra files, both
with markup and pretty titles.

#### Adding Meta-Data to Extra Files

You can add YARD-style `@tag` metadata to the top of any extra file if prefixed
by a `#` hash comment. YARD allows for arbitrary meta-data, but pays special
attention to the tags `@markup`, `@encoding`, and `@title`. Note that there
cannot be any whitespace before the tags. Here is an example of some tag data
in a README:

    # @markup markdown
    # @title The Best Library in the World!
    # @author The Author Name

    This is the best library you will ever meet. Lipsum ...

The `@markup` tag allows you to specify a markup format to use for the file,
including "markdown", "textile", "rdoc", "ruby", "text", "html", or "none"
(no markup). This can be used when the markup cannot be auto-detected using
the extension of the filename, if the file has no extension, or if you want
to override the auto-detection.

By using `@encoding` you can specify a non-standard encoding. Note that
`yardoc --charset` sets the global encoding (for all comments / files),
so if you are using unicode across all your files, you can specify it there.
Using the `@encoding` tag might be used to override the default global
charset, say, if you had a localized `README.jp` file with SJIS data.
Also note that this only affects Ruby 1.9.x, as Ruby 1.8 is not properly
encoding aware.

The `@title` tag allows you to specify a full title name for the document.
By default, YARD uses the filename as the title of the document and lists
it in the file list in the index and file menu. In some cases, the file name
might not be descriptive enough, so YARD allows you to specify a full title:

    contents of TITLE.txt:
    # @title The Title of The Document

Currently all other meta-data is hidden from view, though accessible
programmatically using the {YARD::CodeObjects::ExtraFileObject} class.

You can wrap the meta data section in an HTML comment to prevent it
from being displayed in rendered markdown on GitHub:

    <!--
    # @markup markdown
    # @title The Best Library in the World!
    # @author The Author Name
    -->

    This is the best library you will ever meet. Lipsum ...

<a name="config"></a>

## Configuring YARD

YARD (0.6.2+) supports a global configuration file stored in `~/.yard/config`.
This file is stored as a YAML file and can contain arbitrary keys and values
that can be used by YARD at run-time. YARD defines specific keys that are used
to control various features, and they are listed in {YARD::Config::DEFAULT_CONFIG_OPTIONS}.
A sample configuration file might look like:

    :load_plugins: false
    :ignored_plugins:
      - my_plugin
      - my_other_plugin
    :autoload_plugins:
      - my_autoload_plugin
    :safe_mode: false

You can also view and edit these configuration options from the commandline
using the `yard config` command. To list your configuration, use `yard config --list`.
To view a key, use `yard config ITEM`, and to set it, use `yard config ITEM VALUE`.

<a name="extending"></a>

## Extending YARD

There are many ways to extend YARD to support non-standard Ruby syntax (DSLs),
add new meta-data tags or programmatically access the intermediate metadata
and documentation from code. An overview of YARD's full architecture can be
found in the {file:docs/Overview.md} document.

For information on adding support for Ruby DSLs, see the {file:docs/Handlers.md}
and {file:docs/Parser.md} architecture documents.

For information on adding extra tags, see {file:docs/Tags.md}.

For information on accessing the data YARD stores about your documentation,
look at the {file:docs/CodeObjects.md} architecture document.

<a name="templating"></a>

## Templating YARD

In many cases you may want to change the style of YARD's templates or add extra
information after extending it. The {file:docs/Templates.md} architecture
document covers the basics of how YARD's templating system works.

<a name="plugins"></a>

## Plugin Support

YARD will allow any RubyGem installed on your system (or in your Gemfile)
to be loaded as a plugin provided it has a name with the prefix of
`yard-` or `yard_`. In order to load a plugin, use the `--plugin`
switch with the short-name (name minus the `yard-` prefix) or full-name
of the gem:

    $ gem install yard-custom-plugin
    ...
    $ yard doc --plugin custom-plugin
    or
    $ yard doc --plugin yard-custom-plugin

Note: you can also put this switch in your `.yardopts` file. See the
      `.yardopts` section above for more information.

You can use this functionality to load a custom plugin that
[extend](#extending) YARD's functionality. A good example of this
is the [yard-rspec][yard-rspec] plugin, which adds [RSpec][rspec] specifications
to your documentation (`yardoc` and `yri`). You can try it out by installing
the gem or cloning the project and trying the example:

    $ gem install yard-rspec

 You can then load the plugin with:

    $ yard doc --plugin rspec

YARD also provides a way to temporarily disable plugins on a per-user basis.
To disable a plugin create the file `~/.yard/ignored_plugins` with a list
of plugin names separated by newlines. Note that the `.yard` directory might
not exist, so you may need to create it.

You may find some useful YARD plugins on [RubyGems][RubyGemsQuery] or with
a [Google advanced query][GoogleAdvancedQuery].

[graphviz]:http://www.graphviz.org
[yard-rspec]:http://github.com/lsegal/yard-spec-plugin
[rspec]:http://rspec.info
[GoogleAdvancedQuery]:https://www.google.com/search?q=site%3Arubygems.org+intitle%3A%22yard-%22+OR+intitle%3A%22yard_%22
[RubyGemsQuery]:https://rubygems.org/search?utf8=%E2%9C%93&query=name%3A+yard
