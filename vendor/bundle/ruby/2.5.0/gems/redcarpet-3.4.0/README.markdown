Redcarpet is written with sugar, spice and everything nice
============================================================

[![Build Status](https://travis-ci.org/vmg/redcarpet.svg?branch=master)](https://travis-ci.org/vmg/redcarpet)
[![Dependency Status](https://www.versioneye.com/ruby/redcarpet/badge.svg)](https://www.versioneye.com/ruby/redcarpet)

Redcarpet is a Ruby library for Markdown processing that smells like
butterflies and popcorn.

This library is written by people
---------------------------------

Redcarpet was written by [Vicent Martí](https://github.com/vmg). It is maintained by
[Robin Dupret](https://github.com/robin850) and [Matt Rogers](https://github.com/mattr-).

Redcarpet would not be possible without the [Sundown](https://www.github.com/vmg/sundown)
library and its authors (Natacha Porté, Vicent Martí, and its many awesome contributors).

You can totally install it as a Gem
-----------------------------------

Redcarpet is readily available as a Ruby gem. It will build some native
extensions, but the parser is standalone and requires no installed libraries.
Starting with Redcarpet 3.0, the minimum required Ruby version is 1.9.2 (or Rubinius in 1.9 mode).

    $ [sudo] gem install redcarpet

If you need to use it with Ruby 1.8.7, you will have to stick with 2.3.0:

    $ [sudo] gem install redcarpet -v 2.3.0

The Redcarpet source is available at GitHub:

    $ git clone git://github.com/vmg/redcarpet.git


And it's like *really* simple to use
------------------------------------

The core of the Redcarpet library is the `Redcarpet::Markdown` class. Each
instance of the class is attached to a `Renderer` object; the Markdown class
performs parsing of a document and uses the attached renderer to generate
output.

The `Redcarpet::Markdown` object is encouraged to be instantiated once with the
required settings, and reused between parses.

~~~~~ ruby
# Initializes a Markdown parser
markdown = Redcarpet::Markdown.new(renderer, extensions = {})
~~~~~

Here, the `renderer` variable refers to a renderer object, inheriting
from `Redcarpet::Render::Base`. If the given object has not been
instantiated, the library will do it with default arguments.

Rendering with the `Markdown` object is done through `Markdown#render`.
Unlike in the RedCloth API, the text to render is passed as an argument
and not stored inside the `Markdown` instance, to encourage reusability.
Example:

~~~~~ ruby
markdown.render("This is *bongos*, indeed.")
# => "<p>This is <em>bongos</em>, indeed.</p>"
~~~~~

You can also specify a hash containing the Markdown extensions which the
parser will identify. The following extensions are accepted:

* `:no_intra_emphasis`: do not parse emphasis inside of words.
Strings such as `foo_bar_baz` will not generate `<em>` tags.

* `:tables`: parse tables, PHP-Markdown style.

* `:fenced_code_blocks`: parse fenced code blocks, PHP-Markdown
style. Blocks delimited with 3 or more `~` or backticks will be considered
as code, without the need to be indented. An optional language name may
be added at the end of the opening fence for the code block.

* `:autolink`: parse links even when they are not enclosed in `<>`
characters. Autolinks for the http, https and ftp protocols will be
automatically detected. Email addresses and http links without protocol,
but starting with `www` are also handled.

* `:disable_indented_code_blocks`: do not parse usual markdown
code blocks. Markdown converts text with four spaces at
the front of each line to code blocks. This option
prevents it from doing so. Recommended to use
with `fenced_code_blocks: true`.

* `:strikethrough`: parse strikethrough, PHP-Markdown style.
Two `~` characters mark the start of a strikethrough,
e.g. `this is ~~good~~ bad`.

* `:lax_spacing`: HTML blocks do not require to be surrounded by an
empty line as in the Markdown standard.

* `:space_after_headers`: A space is always required between the hash
at the beginning of a header and its name, e.g. `#this is my header`
would not be a valid header.

* `:superscript`: parse superscripts after the `^` character; contiguous superscripts
are nested together, and complex values can be enclosed in parenthesis, e.g.
`this is the 2^(nd) time`.

* `:underline`: parse underscored emphasis as underlines.
`This is _underlined_ but this is still *italic*`.

* `:highlight`: parse highlights.
`This is ==highlighted==`. It looks like this: `<mark>highlighted</mark>`

* `:quote`: parse quotes.
`This is a "quote"`. It looks like this: `<q>quote</q>`

* `:footnotes`: parse footnotes, PHP-Markdown style. A footnote works very much
like a reference-style link: it consists of a  marker next to the text (e.g.
`This is a sentence.[^1]`) and a footnote definition on its own line anywhere
within the document (e.g. `[^1]: This is a footnote.`).

Example:

~~~ruby
markdown = Redcarpet::Markdown.new(Redcarpet::Render::HTML, autolink: true, tables: true)
 ~~~~~

Darling, I packed you a couple renderers for lunch
--------------------------------------------------

Redcarpet comes with two built-in renderers, `Redcarpet::Render::HTML` and
`Redcarpet::Render::XHTML`, which output HTML and XHTML, respectively. These
renderers are actually implemented in C and hence offer brilliant
performance — several degrees of magnitude faster than other Ruby Markdown
solutions.

All the rendering flags that previously applied only to HTML output have
now been moved to the `Redcarpet::Render::HTML` class, and may be enabled when
instantiating the renderer:

~~~~~ ruby
Redcarpet::Render::HTML.new(render_options = {})
~~~~~

Initializes an HTML renderer. The following flags are available:

* `:filter_html`: do not allow any user-inputted HTML in the output.

* `:no_images`: do not generate any `<img>` tags.

* `:no_links`: do not generate any `<a>` tags.

* `:no_styles`: do not generate any `<style>` tags.

* `:escape_html`: escape any HTML tags. This option has precedence over
`:no_styles`, `:no_links`, `:no_images` and `:filter_html` which means
that any existing tag will be escaped instead of being removed.

* `:safe_links_only`: only generate links for protocols which are considered
safe.

* `:with_toc_data`: add HTML anchors to each header in the output HTML,
to allow linking to each section.

* `:hard_wrap`: insert HTML `<br>` tags inside paragraphs where the original
Markdown document had newlines (by default, Markdown ignores these newlines).

* `:xhtml`: output XHTML-conformant tags. This option is always enabled in the
`Render::XHTML` renderer.

* `:prettify`: add prettyprint classes to `<code>` tags for google-code-prettify.

* `:link_attributes`: hash of extra attributes to add to links.

Example:

~~~~~ ruby
renderer = Redcarpet::Render::HTML.new(no_links: true, hard_wrap: true)
~~~~~


The `HTML` renderer has an alternate version, `Redcarpet::Render::HTML_TOC`,
which will output a table of contents in HTML based on the headers of the
Markdown document.

When instantiating this render object, you can optionally pass a `nesting_level`
option which takes an integer and allows you to make it render only headers
until a specific level.

Redcarpet also includes a plaintext renderer, `Redcarpet::Render::StripDown`, that
strips out all the formatting:

~~~~ ruby
require 'redcarpet'
require 'redcarpet/render_strip'

markdown = Redcarpet::Markdown.new(Redcarpet::Render::StripDown)

markdown.render("**This** _is_ an [example](http://example.org/).")
# => "This is an example (http://example.org/)."
~~~~


And you can even cook your own
------------------------------

Custom renderers are created by inheriting from an existing renderer. The
built-in renderers, `HTML` and `XHTML` may be extended as such:

~~~~~ ruby
# Create a custom renderer that sets a custom class for block-quotes.
class CustomRender < Redcarpet::Render::HTML
  def block_quote(quote)
    %(<blockquote class="my-custom-class">#{quote}</blockquote>)
  end
end

markdown = Redcarpet::Markdown.new(HTMLwithPygments, fenced_code_blocks: true)
~~~~~

But new renderers can also be created from scratch by extending the abstract
base class `Redcarpet::Render::Base` (see `lib/redcarpet/render_man.rb` for
an example implementation of a Manpage renderer):

~~~~~~ ruby
class ManPage < Redcarpet::Render::Base
  # you get the drill -- keep going from here
end
~~~~~

The following instance methods may be implemented by the renderer:

### Block-level calls

If the return value of the method is `nil`, the block will be skipped.
Therefore, make sure that your renderer has at least a `paragraph` method
implemented. If the method for a document element is not implemented, the
block will be skipped.

Example:

~~~~ ruby
class RenderWithoutCode < Redcarpet::Render::HTML
  def block_code(code, language)
    nil
  end
end
~~~~

* block_code(code, language)
* block_quote(quote)
* block_html(raw_html)
* footnotes(content)
* footnote_def(content, number)
* header(text, header_level)
* hrule()
* list(contents, list_type)
* list_item(text, list_type)
* paragraph(text)
* table(header, body)
* table_row(content)
* table_cell(content, alignment)

### Span-level calls

A return value of `nil` will not output any data. If the method for
a document element is not implemented, the contents of the span will
be copied verbatim:

* autolink(link, link_type)
* codespan(code)
* double_emphasis(text)
* emphasis(text)
* image(link, title, alt_text)
* linebreak()
* link(link, title, content)
* raw_html(raw_html)
* triple_emphasis(text)
* strikethrough(text)
* superscript(text)
* underline(text)
* highlight(text)
* quote(text)
* footnote_ref(number)

**Note**: When overriding a renderer's method, be sure to return a HTML
element with a level that matches the level of that method (e.g. return a
block element when overriding a block-level callback). Otherwise, the output
may be unexpected.

### Low level rendering

* entity(text)
* normal_text(text)

### Header of the document

Rendered before any another elements:

* doc_header()

### Footer of the document

Rendered after all the other elements:

* doc_footer()

### Pre/post-process

Special callback: preprocess or postprocess the whole document before
or after the rendering process begins:

* preprocess(full_document)
* postprocess(full_document)

You can look at
["How to extend the Redcarpet 2 Markdown library?"](http://dev.af83.com/2012/02/27/howto-extend-the-redcarpet2-markdown-lib.html)
for some more explanations.

Also, now our Pants are much smarter
------------------------------------

Redcarpet 2 comes with a standalone [SmartyPants](
http://daringfireball.net/projects/smartypants/) implementation. It is fully
compliant with the original implementation. It is the fastest SmartyPants
parser there is, with a difference of several orders of magnitude.

The SmartyPants parser can be found in `Redcarpet::Render::SmartyPants`. It has
been implemented as a module, so it can be used standalone or as a mixin.

When mixed with a Renderer class, it will override the `postprocess` method
to perform SmartyPants replacements once the rendering is complete.

~~~~ ruby
# Mixin
class HTMLWithPants < Redcarpet::Render::HTML
  include Redcarpet::Render::SmartyPants
end

# Standalone
Redcarpet::Render::SmartyPants.render("<p>Oh SmartyPants, you're so crazy...</p>")
~~~~~

SmartyPants works on top of already-rendered HTML, and will ignore replacements
inside the content of HTML tags and inside specific HTML blocks such as
`<code>` or `<pre>`.

What? You really want to mix Markdown renderers?
------------------------------------------------

Redcarpet used to be a drop-in replacement for Redcloth. This is no longer the
case since version 2 -- it now has its own API, but retains the old name. Yes,
that does mean that Redcarpet is not backwards-compatible with the 1.X
versions.

Each renderer has its own API and its own set of extensions: you should choose one
(it doesn't have to be Redcarpet, though that would be great!), write your
software accordingly, and force your users to install it. That's the
only way to have reliable and predictable Markdown output on your program.

Markdown is already ill-specified enough; if you create software that is
renderer-independent, the results will be completely unreliable!

Still, if major forces (let's say, tornadoes or other natural disasters) force you
to keep a Markdown-compatibility layer, Redcarpet also supports this:

~~~~~ ruby
require 'redcarpet/compat'
~~~~~

Requiring the compatibility library will declare a `Markdown` class with the
classical RedCloth API, e.g.

~~~~~ ruby
Markdown.new('this is my text').to_html
~~~~~

This class renders 100% standards compliant Markdown with 0 extensions. Nada.
Don't even try to enable extensions with a compatibility layer, because
that's a maintenance nightmare and won't work.

On a related topic: if your Markdown gem has a `lib/markdown.rb` file that
monkeypatches the Markdown class, you're a terrible human being. Just saying.

Boring legal stuff
------------------

Copyright (c) 2011-2016, Vicent Martí

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
