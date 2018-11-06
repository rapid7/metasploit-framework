# @title Templates Architecture

# Templates Architecture

Templates are the main component in the output rendering process of YARD,
which is invoked when conventional HTML/text output needs to be rendered
for a set of code objects.

## Design Goals

The general design attempts to be as abstracted from actual content and templates
as possible. Unlike RDoc which uses one file to describe the entire template,
YARD splits up the rendering of code objects into small components, allowing
template modification for smaller subsets of a full template without having to
duplicate the entire template itself. This is necessary because of YARD's support
for plugins. YARD is designed for extensibility by external plugins, and because
of this, no one plugin can be responsible for the entire template because no
one plugin knows about the other plugins being used. For instance, if an RSpec
plugin was added to support and document specifications in class templates,
this information would need to be transparently added to the template to work
in conjunction with any other plugin that performed similar template modifications.
The design goals can be summarized as follows:

  1. Output should be able to be rendered for any arbitrary format with little
     modification to YARD's source code. The addition of extra templates should
     be sufficient.
  2. The output rendered for an object should independently rendered data
     from arbitrary sources. These independent components are called "sections".
  3. Sections should be able to be inserted into any object without affecting
     any existing sections in the document. This allows for easy modification
     of templates by plugins.

## Templates

Template modules are the objects used to orchestrate the design goals listed
above. Specifically, they organize the sections and render the template contents
depending on the format.

## Engine

The Engine class orchestrates the creation and rendering of Template modules and
handles serialization or specific rendering scenarios (like HTML). To create
a template, use the {YARD::Templates::Engine.template template} method. The two most
common methods used to initiate output are the {YARD::Templates::Engine.render render}
and {YARD::Templates::Engine.generate generate} methods which generate and
optionally serialize output to a file. The latter, `#generate`, is used
specially to generate HTML documentation and copy over assets that may be
needed. For instance, an object may be rendered with:

    YARD::Templates::Engine.render(:object => myobject)

A set of objects may be rendered into HTML documentation by using:

    # all_objects is an array of module and class objects
    # options includes a :serializer key to copy output to the file system
    YARD::Templates::Engine.generate(all_objects, options)

Note that these methods should not be called directly. The {YARD::CodeObjects::Base}
class has a {YARD::CodeObjects::Base#format #format} helper method to render an
object. For instance, the above render example is equivalent to the simple
call `myobject.format`. The `generate` method is a special kind of render
and is called from the {YARD::CLI::Yardoc} command line utility.

## Template Options

A template keeps state when it is rendering output. This state is kept in
an options hash which is initially passed to it during instantiation. Some
default options set the template style (`:template`), the output format (`:format`),
and the serializer to use (`:serializer`). This options hash is modifiable
from all methods seen above. For example, initializing a template to output as
HTML instead of text can be done as follows:

    myobject.format(:format => :html)

## Serializer

This class abstracts the logic involved in deciding how to serialize data to
the expected endpoint. For instance, there is both a {YARD::Serializers::StdoutSerializer StdoutSerializer}
and {YARD::Serializers::FileSystemSerializer FileSystemSerializer} class for
outputting to console or to a file respectively. When endpoints with locations
are used (like files or URLs), the serializer implements the {YARD::Serializers::Base#serialized_path #serialized_path}
method. This allows the translation from a code object to its path at the endpoint,
which enables inter-document linking.

Rendered objects are automatically serialized using the object if present,
otherwise the rendered object is returned as a string to its parent. Nested
Templates automatically set the serializer to nil so that they return
as a String to their parent.

## Creating a Template

Templates are represented by a directory inside the {YARD::Templates::Engine.template_paths}
on disk. A standard template directory looks like the following tree:

    (Assuming templates/ is a template path)
    templates
    `-- default
        |-- class
        |   |-- dot
        |   |   |-- setup.rb
        |   |   `-- superklass.erb
        |   |-- html
        |   |   |-- constructor_details.erb
        |   |   |-- setup.rb
        |   |   `-- subclasses.erb
        |   |-- setup.rb
        |   `-- text
        |       |-- setup.rb
        |       `-- subclasses.erb
        |-- docstring
        |   |-- html
        |   |   |-- abstract.erb
        |   |   |-- deprecated.erb
        |   |   |-- index.erb
        |   |   `-- text.erb
        |   |-- setup.rb
        |   `-- text
        |       |-- abstract.erb
        |       |-- deprecated.erb
        |       |-- index.erb
        |       `-- text.erb

The path `default` refers to the template style (:template key in options hash)
and the directories at the next level (such as `class`) refer to template
`:type` (options hash key) for a template. The next directory refers to the
output format being used defined by the `:format` template option.

As we saw in the above example, the format option can be set to `:html`, which
would use the `html/` directory instead of `text/`. Finally, the individual .erb
files are the sections that make up the template.

Note that the subdirectory `html/` is also its own "template" that inherits
from the parent directory. We will see more on this later.

## setup.rb

Every template should have at least one `setup.rb` file that defines the
{YARD::Templates::Template#init #init} method to set the
{YARD::Templates::Template#sections #sections} used by the template. If
a setup.rb is not defined in the template itself, there should be a template
that is inherited (via parent directory or explicitly) that sets the sections
on a newly created template.

A standard setup.rb file looks like:

    def init
      sections :section1, :section2, :section3
    end

## Sections

Sections are smaller components that correlate to template
fragments. Practically speaking, a section can either be a template fragment
(a conventional .erb file or other supported templating language), a method
(which returns a String) or another {YARD::Templates::Template} (which in turn has its own
list of sections).

## Nested Sections

Sections often require the ability to encapsulate a set of sub-sections in markup
(HTML, for instance). Rather than use heavier Template subclass objects, a more
lightweight solution is to nest a set of sub-sections as a list that follows
a section, for example:

    def init
      sections :header, [:section_a, :section_b]
    end

The above example nests `section_a` and `section_b` within the `header` section.
Practically speaking, these sections can be placed in the result by `yield`ing
to them. A sample header.erb template might contain:

    <h2>Header</h2>
    <div id="contents">
      <%= yieldall %>
    </div>

This template code would place the output of `section_a` and `section_b` within
the above div element. Using `yieldall`, we can also change the object that is being
rendered. For example, we may want to yield the first method of the class.
We can do this like so:

    <h2>First method</h2>
    <%= yieldall :object => object.meths.first %>

This would run the nested sections for the method object instead of the class.

Note that `yieldall` yields to all subsections, whereas `yield` will yield
to each individually (in order) until there are no more left to yield to.
In the vast majority of cases, you'd want to use `yieldall`, since `yield`
makes it hard for users to override your template.

## Inheriting Templates

Parent directory templates are automatically inherited (or mixed in, to be
more accurate) by the current template. This means that the 'default/class/html'
template automatically inherits from 'default/class'. This also means that anything
defined in 'default/class/setup.rb' can be overridden by 'default/class/html/setup.rb'.

Since the Template module is a module, and not a class, they can be mixed in
explicitly (via include/extend) from other templates, which allows templates
to share erb files or helper logic. The 'default/class' template explicitly
mixes in the 'default/module' template, since it uses much of the same sections.
This is done with the helper {YARD::Templates::Template::ClassMethods#T T} method, which
is simply a shorthand for {YARD::Templates::Engine.template Engine.template}.
It can then override (using standard inheritance) the sections from the module
template and insert sections pertaining to classes. This is one of the design
goals described above.

For instance, the first line in `default/class/html/setup.rb` is:

    include T('default/module/html')

This includes the 'default/module/html', which means it also includes 'default/module'
by extension. This allows class to make use of any of module's erb files.

## Inserting and Traversing Sections

The ability to insert sections was mentioned above. The class template, for
instance, will modify the #init method to insert class specific sections:

    def init
      super
      sections.place(:subclasses).before(:children)
      sections.delete(:children)
      sections.place([:constructor_details, [T('method_details')]]).before(:methodmissing)
    end

Observe how sections has been modified after the super method was called (the
super method would have been defined in `default/module/setup.rb`). The
`sections` object is of the {YARD::Templates::Section} class and allows sections to be inserted
before or after another section using {Array#place} by it's given name rather
than index. This allows the overriding of templates in a way that does not
depend on where the section is located (since it may have been overridden by
another module).

You can also use `sections[:name]` to find the first child section named `:name`.
For instance, with the following sections declaration:

    sections :a, [:b, :c, [:d]]

You can get to the :d section with:

    sections[:a][:c][:d]

You can use this to insert a section inside a nested set without using indexed
access. The following command would result in `[:a, [:b, :c, [:d, :e]]]`:

    sections[:a][:c].place(:e).after(:d)

There are also two methods, {Insertion#before_any} and {Insertion#after_any},
which allow you to insert sections before or after the first matching section name
recursively. The above example could simply be rewritten as:

    sections.place(:e).after_any(:d)

## Overriding Templates by Registering a Template Path

Inheriting templates explicitly is useful when creating a customized template
that wants to take advantage of code re-use. However, most users who want
to customize YARD templates will want to override existing behaviour without
creating a template from scratch.

YARD solves this problem by allowing other template paths to be registered.
Because template modules are represented by a relative path such as 'default/class',
they can be found within any of the registered template paths. A new template
path is registered as:

    YARD::Templates::Engine.register_template_path '/path/to/mytemplates'

At this point, any time the 'default/class' template is loaded, the template
will first be looked for inside the newly registered template path. If found,
it will be used as the template module, with the modules from the other
template paths implicitly mixed in.

Therefore, by using the same directory structure as a builtin YARD template,
a user can customize or override individual templates as if the old ones were
inherited. A real world example would further modify the 'default/class' template
seen above by creating such a path in our '/path/to/mytemplates' custom template
path:

    /path/to/mytemplates/:
    |-- class
    |   |-- html
    |   |   |-- customsection.erb
    |   |-- setup.rb

The `setup.rb` file would look like:

    def init
      super
      sections.push :customsection
    end

Now, when a class object is formatted as HTML, our customsection.erb will be
appended to the rendered data.


### Overriding Stylesheets and Javascripts

Template authors can override existing stylesheets and javascripts by creating
a file with the same name as existing files within the `fulldoc` template. The
documentation output will utilize the new replacement file.

YARD's `fulldoc` template defines three stylesheets:

    /yard/templates/default/:
    |-- fulldoc
    |   |-- html
    |   |   |-- css
    |   |   |   |-- common.css
    |   |   |   |-- full_list.css
    |   |   |   |-- style.css

The `style.css` is the primary stylesheet for the HTML output.

The `full_list.css` is an additional stylesheet loaded specifically for the
search field menus (i.e. class list, method list, and file list).

The `common.css` is an empty css file that an template author can easily override
to provide custom styles for their plugin. However, if a user installs multiple
plugins that utilize this same file to deliver styles, it is possible that they
will be overridden.

YARD's `fulldoc` template defines three javascript files:

    /yard/templates/default/:
    |-- fulldoc
    |   |-- html
    |   |   |-- js
    |   |   |   |-- app.js
    |   |   |   |-- full_list.js
    |   |   |   |-- jquery.js

The `app.js` is the primary javascript file for the HTML output.

The `full_list.js` defines additional javascript loaded specifically for the
search field menus (i.e. class list, method list, and file list).

The `jquery.js` is copy of the jquery javascript library.

### Adding a Custom Stylesheet or Javascript

To load additional stylesheets and javascripts with every page (except the search
field menus) generated from the base `layout` template:

  1. Define your own custom stylesheet and/or javascript file
     (default/ is the default template name inside of the /template root directory):

         /template/default/:
         |-- fulldoc
         |   |-- html
         |   |   |-- css
         |   |   |   |-- custom.css
         |   |   |-- js
         |   |   |   |-- custom.js

  2. Create a `setup.rb` in the `layout` template directory and override the methods
     `stylesheets` and `javascripts`. The path to the template would be:

         /template/default/:
         |-- layout
         |   |-- html
         |   |   |-- setup.rb

     And the code would look like:

         def stylesheets
           # Load the existing stylesheets while appending the custom one
           super + %w(css/custom.css)
         end

         def javascripts
           # Load the existing javascripts while appending the custom one
           super + %w(js/custom.js)
         end


To load additional stylesheets and javascripts for the search menus loaded from
the `fulldoc` template:

  1. Define your own custom stylesheet and/or javascript file.

        /path/to/mytemplates/:
        |-- fulldoc
        |   |-- html
        |   |   |-- css
        |   |   |   |-- custom_full_menu.css
        |   |   |-- js
        |   |   |   |-- custom_full_menu.js


  3. Override the methods `stylesheets_full_list` and `javascripts_full_list`
     in the `setup.rb` file inside fulldoc/html.

        def stylesheets_full_list
          # Load the existing stylesheets while appending the custom one
          super + %w(css/custom.css)
        end

        def javascripts_full_list
          # Load the existing javascripts while appending the custom one
          super + %w(js/custom.js)
        end

### Overriding Search Menus

By default YARD's `fulldoc` template generates three search fields:

  * Class List
  * Method List
  * File List

Their contents are rendered in methods within the `fulldoc` template:

  * `generate_class_list`
  * `generate_method_list`
  * `generate_file_list`

To override these lists you will need to:

  1. Create a `setup.rb` in the `fulldoc` template directory and override the
     particular method.

         /path/to/mytemplates/:
         |-- fulldoc
         |   |-- html
         |   |   |-- setup.rb

         def generate_method_list
           @items = prune_method_listing(Registry.all(:method), false)
           @items = @items.reject {|m| m.name.to_s =~ /=$/ && m.is_attribute? }

           # Here we changed the functionality to reverse the order of displayed methods
           @items = @items.sort_by {|m| m.name.to_s }.reverse
           @list_title = "Method List"
           @list_type = "methods"
           asset('method_list.html', erb(:full_list))
         end

### Adding Additional Search Menus

By default YARD's `fulldoc` template generates three search fields:

  * Class List
  * Method List
  * File List

These are defined in the `layout` template method `menu_lists` and pulled into
the `fulldoc` template through a similarly named method.

To load an additional menu item:


  1. Create a `setup.rb` in the `layout` template directory and override the methods
   `menu_lists`. The `type` informs the search field the name of the file.
    The `title` is the name that appears above the section when viewed in frames.
    The `search_title` is the name that appears in the search field tab on the page.


        /path/to/mytemplates/:
        |-- layout
        |   |-- html
        |   |   |-- setup.rb

        def menu_lists
          # Load the existing menus
          super + [ { :type => 'feature', :title => 'Features', :search_title => 'Feature List' } ]
        end

  2. Create a `setup.rb` in the `fulldoc` template directory and create a method
     to generate a menu for the specified `type`.
     The method `generate_assets` will look for a function with a signature prefixed
     with `generate`, the type value specified, and the suffix `list`. Within that
     method you can configure and load the specific objects you wish to display.

         /path/to/mytemplates/:
         |-- fulldoc
         |   |-- html
         |   |   |-- setup.rb

         def generate_feature_list

           # load all the features from the Registry
           @items = Registry.all(:feature)
           @list_title = "Feature List"
           @list_type = "feature"

           # optional: the specified stylesheet class
           # when not specified it will default to the value of @list_type
           @list_class = "class"

           # Generate the full list html file with named feature_list.html
           # @note this file must be match the name of the type
           asset('feature_list.html', erb(:full_list))
         end
