# @title Tags Overview

# Tags Overview

Tags represent meta-data as well as behavioural data that can be added to
documentation through the `@tag` style syntax. As mentioned, there are two
basic types of tags in YARD, "meta-data tags" and "behavioural tags", the
latter is more often known as "directives". These two tag types can be
visually identified by their prefix. Meta-data tags have a `@` prefix,
while directives have a prefix of `@!` to indicate that the directive
performs some potentially mutable action on or with the docstring. The
two tag types would be used in the following way, respectively:

    # @meta_data_tag some data
    # @!directive_tag some data
    class Foo; end

This document describes how tags can be specified, how they affect your
documentation, and how to use specific built-in tags in YARD, as well
as how to define custom tags.

## Meta-Data Tags

Meta-data tags are useful to add arbitrary meta-data about a documented
object. These tags simply add data to objects that can be looked up later,
either programmatically, or displayed in templates. The benefit to describing
objects using meta-data tags is that your documentation can be organized
semantically. Rather than having a huge listing of text with no distinction
of what each paragraph is discussing, tags allow you to focus in on specific
elements of your documentation.

For example, describing parameters of a method can often be important to your
documentation, but should not be mixed up with the documentation that describes
what the method itself does. In this case, separating the parameter documentation
into {tag:param} tags can yield much better organized documentation, both in
source and in your output, without having to manually format the data using
standard markup.

All of this meta-data can be easily parsed by tools and used both in your templates
as well as in code checker tools. An example of how you can leverage tags
programmatically is shown in the {tag:todo} tag, which lists a small snippet of
Ruby code that can list all of your TODO items, if they are properly tagged.

Custom meta-data tags can be added either programmatically or via the YARD
command-line. This is discussed in the "[Adding Custom Tags](#Adding_Custom_Tags)"
section.

A list of built-in meta-data tags are found below in the [Tag List](#Tag_List).

## Directives

Directives are similar to meta-data tags in the way they are specified, but they
do not add meta-data to the object directly. Instead, they affect the parsing
context and objects themselves, allowing a developer to create objects
(like methods) outright, rather than simply add text to an existing object.
Directives have a `@!` prefix to differentiate these tags from meta-data tags,
as well as to indicate that the tag may modify or create new objects when
it is called.

A list of built-in directives are found below in the [Directive List](#Directive_List).

## Tag Syntax

Tags begin with the `@` or `@!` prefix at the start of a comment line, followed
immediately by the tag name, and then optional tag data (if the tag requires it).
Unless otherwise specified by documentation for the tag, all "description" text
is considered free-form data and can include any arbitrary textual data.

### Multi-line Tags

Tags can span multiple lines if the subsequent lines are indented by more than
one space. The typical convention is to indent subsequent lines by 2 spaces.
In the following example, `@tagname` will have the text *"This is indented tag data"*:

    # @tagname This is
    #   indented tag data
    # but this is not

For most tags, newlines and indented data are not significant and do not impact
the result of the tag. In other words, you can decide to span a tag onto multiple
lines at any point by creating an indented block. However, some tags like
{tag:example}, {tag:overload}, {tag:!macro}, {tag:!method}, and {tag:!attribute}
rely on the first line for special information about the tag, and you cannot
split this first line up. For instance, the {tag:example} tag uses the first line
to indicate the example's title.

### Common Tag Syntaxes

Although custom tags can be parsed in any way, the built-in tags follow a few
common syntax structures by convention in order to simplify the syntax. The
following syntaxes are available:

1. **Freeform data** &mdash; In this case, any amount of textual data is allowed,
  including no data. In some cases, no data is necessary for the tag.
2. **Freeform data with a types specifier list** &mdash; Mostly freeform data
  beginning with an *optional* types specifier list surrounded in `[brackets]`.
  Note that for extensibility, other bracket types are allowed, such as `<>`,
  `()` and `{}`. The contents of the list are discussed in detail below.
3. **Freeform data with a name and types specifier list** &mdash; freeform
  data beginning with an *optional* types list, as well as a name key, placed
  either before or after the types list. The name key is *required*. Note that
  for extensibility, the name can be placed *before* the types list, like:
  `name [Types] description`. In this case, a separating space is not required
  between the name and types, and you can still use any of the other brackets
  that the type specifier list allows.
4. **Freeform data with title** &mdash; freeform data where the first line cannot
  be split into multiple lines. The first line must also always refer to the
  "title" portion, and therefore, if there is no title, the first line must
  be blank. The "title" might occasionally be listed by another name in tag
  documentation, however, you can identify this syntax by the existence of
  a multi-line signature with "Indented block" on the second line.

In the tag list below, the term "description" implies freeform data, `[Types]`
implies a types specifier list, "name" implies a name key, and "title" implies
the first line is a newline significant field that cannot be split into multiple
lines.

### Types Specifier List

In some cases, a tag will allow for a "types specifier list"; this will be evident
from the use of the `[Types]` syntax in the tag signature. A types specifier list
is a comma separated list of types, most often classes or modules, but occasionally
literals. For example, the following {tag:return} tag lists a set of types returned
by a method:

    # Finds an object or list of objects in the db using a query
    # @return [String, Array<String>, nil] the object or objects to
    #   find in the database. Can be nil.
    def find(query) finder_code_here end

A list of conventions for type names is specified below. Typically, however,
any Ruby literal or class/module is allowed here. Duck-types (method names
prefixed with "#") are also allowed.

Note that the type specifier list is always an optional field and can be omitted
when present in a tag signature. This is the reason why it is surrounded by
brackets. It is also a freeform list, and can contain any list of values, though
a set of conventions for how to list types is described below.

### Type List Conventions

<p class="note">
  A list of examples of common type listings and what they translate into is
  available at <a href="http://yardoc.org/types">http://yardoc.org/types</a>.
</p>

Typically, a type list contains a list of classes or modules that are associated
with the tag. In some cases, however, certain special values are allowed or required
to be listed. This section discusses the syntax for specifying Ruby types inside of
type specifier lists, as well as the other non-Ruby types that are accepted by
convention in these lists.

It's important to realize that the conventions listed here may not always adequately
describe every type signature, and is not meant to be a complete syntax. This is
why the types specifier list is freeform and can contain any set of values. The
conventions defined here are only conventions, and if they do not work for your
type specifications, you can define your own appropriate conventions.

Note that a types specifier list might also be used for non-Type values. In this
case, the tag documentation will describe what values are allowed within the
type specifier list.

#### Class or Module Types

Any Ruby type is allowed as a class or module type. Such a type is simply the name
of the class or module.

Note that one extra type that is accepted by convention is the `Boolean` type,
which represents both the `TrueClass` and `FalseClass` types. This type does not
exist in Ruby, however.

#### Parametrized Types

In addition to basic types (like String or Array), YARD conventions allow for
a "generics" like syntax to specify container objects or other parametrized types.
The syntax is `Type<SubType, OtherSubType, ...>`. For instance, an Array might
contain only String objects, in which case the type specification would be
`Array<String>`. Multiple parametrized types can be listed, separated by commas.

Note that parametrized types are typically not order-dependent, in other words,
a list of parametrized types can occur in any order inside of a type. An array
specified as `Array<String, Fixnum>` can contain any amount of Strings or Fixnums,
in any order. When the order matters, use "order-dependent lists", described below.

#### Duck-Types

Duck-types are allowed in type specifier lists, and are identified by method
names beginning with the "#" prefix. Typically, duck-types are recommended
for {tag:param} tags only, though they can be used in other tags if needed.
The following example shows a method that takes a parameter of any type
that responds to the "read" method:

    # Reads from any I/O object.
    # @param io [#read] the input object to read from
    def read(io) io.read end

#### Hashes

Hashes can be specified either via the parametrized type discussed above,
in the form `Hash<KeyType, ValueType>`, or using the hash specific syntax:
`Hash{KeyTypes=>ValueTypes}`. In the latter case, KeyTypes or ValueTypes can
also be a list of types separated by commas.

#### Order-Dependent Lists

An order dependent list is a set of types surrounded by "()" and separated by
commas. This list must contain exactly those types in exactly the order specified.
For instance, an Array containing a String, Fixnum and Hash in that order (and
having exactly those 3 elements) would be listed as: `Array<(String, Fixnum, Hash)>`.

#### Literals

Some literals are accepted by virtue of being Ruby literals, but also by YARD
conventions. Here is a non-exhaustive list of certain accepted literal values:

* `true`, `false`, `nil` &mdash; used when a method returns these explicit literal
  values. Note that if your method returns both `true` or `false`, you should use
  the `Boolean` conventional type instead.
* `self` &mdash; has the same meaning as Ruby's "self" keyword in the context of
  parameters or return types. Recommended mostly for {tag:return} tags that are
  chainable.
* `void` &mdash; indicates that the type for this tag is explicitly undefined.
  Mostly used to specify {tag:return} tags that do not care about their return
  value. Using a `void` return tag is recommended over no type, because it makes
  the documentation more explicit about what the user should expect. YARD will
  also add a note for the user if they have undefined return types, making things
  clear that they should not use the return value of such a method.

<a name="reftags"></a>

### Reference Tags

<p class="note">
  Reference tag syntax applies only to meta-data tags, not directives.
</p>

If a tag's data begins with `(see OBJECT)` it is considered a "reference tag".
A reference tag literally copies the tag data by the given tag name from the
specified OBJECT. For instance, a method may copy all {tag:param} tags from
a given object using the reference tag syntax:

    # @param user [String] the username for the operation
    # @param host [String] the host that this user is associated with
    # @param time [Time] the time that this operation took place
    def clean(user, host, time = Time.now) end

    # @param (see #clean)
    def activate(user, host, time = Time.now) end

## Adding Custom Tags

<p class="note">If a tag is specific to a given project, consider namespacing
  it by naming it in the form <tt>projectname.tagname</tt>, ie.,
  <tt>yard.tag_signature</tt>.</p>

Custom tags can be added to YARD either via the command-line or programmatically.
The programmatic method is not discussed in this document, but rather in the
{file:docs/TagsArch.md} document.

To add a custom tag via the command-line or .yardopts file, you can use the
`--*-tag` options. A few different options are available for the common tag
syntaxes described above. For example, to add a basic freeform tag, use:

    !!!sh
    $ yard doc --tag rest_url:"REST URL"

This will register the `@rest_url` tag for use in your documentation and display
this tag in HTML output wherever it is used with the heading "REST URL".
Note that the tag title should follow the tag name with a colon (`:`). Other
tag syntaxes exist, such as the type specifier list freeform tag
(`--type-tag`), or a named key tag with types (`--type-name-tag`).

If you want to create a tag but not display it in output (it is only for
programmatic use), add `--hide-tag tagname` after the definition:

    !!!sh
    $ yard doc --tag complexity:"McCabe Complexity" --hide-tag complexity

Note that you might not need a tag title if you are hiding it. The title
part can be omitted.

{yard:include_tags}

