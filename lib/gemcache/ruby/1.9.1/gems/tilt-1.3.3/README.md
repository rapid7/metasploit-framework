Tilt
====

Tilt is a thin interface over a bunch of different Ruby template engines in
an attempt to make their usage as generic possible. This is useful for web
frameworks, static site generators, and other systems that support multiple
template engines but don't want to code for each of them individually.

The following features are supported for all template engines (assuming the
feature is relevant to the engine):

 * Custom template evaluation scopes / bindings
 * Ability to pass locals to template evaluation
 * Support for passing a block to template evaluation for "yield"
 * Backtraces with correct filenames and line numbers
 * Template file caching and reloading
 * Fast, method-based template source compilation

The primary goal is to get all of the things listed above right for all
template engines included in the distribution.

Support for these template engines is included with the package:

    ENGINE                     FILE EXTENSIONS         REQUIRED LIBRARIES
    -------------------------- ----------------------- ----------------------------
    ERB                        .erb, .rhtml            none (included ruby stdlib)
    Interpolated String        .str                    none (included ruby core)
    Erubis                     .erb, .rhtml, .erubis   erubis
    Haml                       .haml                   haml
    Sass                       .sass                   haml (< 3.1) or sass (>= 3.1)
    Scss                       .scss                   haml (< 3.1) or sass (>= 3.1)
    Less CSS                   .less                   less
    Builder                    .builder                builder
    Liquid                     .liquid                 liquid
    RDiscount                  .markdown, .mkd, .md    rdiscount
    Redcarpet                  .markdown, .mkd, .md    redcarpet
    BlueCloth                  .markdown, .mkd, .md    bluecloth
    Kramdown                   .markdown, .mkd, .md    kramdown
    Maruku                     .markdown, .mkd, .md    maruku
    RedCloth                   .textile                redcloth
    RDoc                       .rdoc                   rdoc
    Radius                     .radius                 radius
    Markaby                    .mab                    markaby
    Nokogiri                   .nokogiri               nokogiri
    CoffeeScript               .coffee                 coffee-script (+ javascript)
    Creole (Wiki markup)       .wiki, .creole          creole
    WikiCloth (Wiki markup)    .wiki, .mediawiki, .mw  wikicloth
    Yajl                       .yajl                   yajl-ruby

These template engines ship with their own Tilt integration:

    ENGINE                     FILE EXTENSIONS   REQUIRED LIBRARIES
    -------------------------- ----------------- ----------------------------
    Slim                       .slim             slim (>= 0.7)
    Embedded JavaScript                          sprockets
    Embedded CoffeeScript                        sprockets
    JST                                          sprockets

See [TEMPLATES.md][t] for detailed information on template engine
options and supported features.

[t]: http://github.com/rtomayko/tilt/blob/master/TEMPLATES.md
   "Tilt Template Engine Documentation"

Basic Usage
-----------

Instant gratification:

    require 'erb'
    require 'tilt'
    template = Tilt.new('templates/foo.erb')
    => #<Tilt::ERBTemplate @file="templates/foo.rb" ...>
    output = template.render
    => "Hello world!"

It's recommended that calling programs explicitly require template engine
libraries (like 'erb' above) at load time. Tilt attempts to lazy require the
template engine library the first time a template is created but this is
prone to error in threaded environments.

The `Tilt` module contains generic implementation classes for all supported
template engines. Each template class adheres to the same interface for
creation and rendering. In the instant gratification example, we let Tilt
determine the template implementation class based on the filename, but
`Tilt::Template` implementations can also be used directly:

    template = Tilt::HamlTemplate.new('templates/foo.haml')
    output = template.render

The `render` method takes an optional evaluation scope and locals hash
arguments. Here, the template is evaluated within the context of the
`Person` object with locals `x` and `y`:

    template = Tilt::ERBTemplate.new('templates/foo.erb')
    joe = Person.find('joe')
    output = template.render(joe, :x => 35, :y => 42)

If no scope is provided, the template is evaluated within the context of an
object created with `Object.new`.

A single `Template` instance's `render` method may be called multiple times
with different scope and locals arguments. Continuing the previous example,
we render the same compiled template but this time in jane's scope:

    jane = Person.find('jane')
    output = template.render(jane, :x => 22, :y => nil)

Blocks can be passed to `render` for templates that support running
arbitrary ruby code (usually with some form of `yield`). For instance,
assuming the following in `foo.erb`:

    Hey <%= yield %>!

The block passed to `render` is called on `yield`:

    template = Tilt::ERBTemplate.new('foo.erb')
    template.render { 'Joe' }
    # => "Hey Joe!"

Template Mappings
-----------------

The `Tilt` module includes methods for associating template implementation
classes with filename patterns and for locating/instantiating template
classes based on those associations.

The `Tilt::register` method associates a filename pattern with a specific
template implementation. To use ERB for files ending in a `.bar` extension:

     >> Tilt.register Tilt::ERBTemplate, 'bar'
     >> Tilt.new('views/foo.bar')
     => #<Tilt::ERBTemplate @file="views/foo.bar" ...>

Retrieving the template class for a file or file extension:

     >> Tilt['foo.bar']
     => Tilt::ERBTemplate
     >> Tilt['haml']
     => Tilt::HamlTemplate

It's also possible to register template file mappings that are more specific
than a file extension. To use Erubis for `bar.erb` but ERB for all other `.erb`
files:

     >> Tilt.register Tilt::ErubisTemplate, 'bar.erb'
     >> Tilt.new('views/foo.erb')
     => Tilt::ERBTemplate
     >> Tilt.new('views/bar.erb')
     => Tilt::ErubisTemplate

The template class is determined by searching for a series of decreasingly
specific name patterns. When creating a new template with
`Tilt.new('views/foo.html.erb')`, we check for the following template
mappings:

  1. `views/foo.html.erb`
  2. `foo.html.erb`
  3. `html.erb`
  4. `erb`

### Fallback mode

If there are more than one template class registered for a file extension, Tilt
will automatically try to load the version that works on your machine:

  1. If any of the template engines has been loaded already: Use that one.
  2. If not, it will try to initialize each of the classes with an empty template.
  3. Tilt will use the first that doesn't raise an exception.
  4. If however *all* of them failed, Tilt will raise the exception of the first
     template engine, since that was the most preferred one.

Template classes that were registered *last* would be tried first. Because the
Markdown extensions are registered like this:

    Tilt.register Tilt::BlueClothTemplate, 'md'
    Tilt.register Tilt::RDiscountTemplate, 'md'

Tilt will first try RDiscount and then BlueCloth. You could say that RDiscount
has a *higher priority* than BlueCloth.

The fallback mode works nicely when you just need to render an ERB or Markdown
template, but if you depend on a specific implementation, you should use #prefer:

    # Prefer BlueCloth for all its registered extensions (markdown, mkd, md)
    Tilt.prefer Tilt::BlueClothTemplate
    
    # Prefer Erubis for .erb only:
    Tilt.prefer Tilt::ErubisTemplate, 'erb'

When a file extension has a preferred template class, Tilt will *always* use
that class, even if it raises an exception.

Template Compilation
--------------------

Tilt compiles generated Ruby source code produced by template engines and reuses
it on subsequent template invocations. Benchmarks show this yields a 5x-10x
performance increase over evaluating the Ruby source on each invocation.

Template compilation is currently supported for these template engines:
StringTemplate, ERB, Erubis, Haml, Nokogiri, Builder and Yajl.

LICENSE
-------

Tilt is Copyright (c) 2010 [Ryan Tomayko](http://tomayko.com/about) and
distributed under the MIT license. See the `COPYING` file for more info.
