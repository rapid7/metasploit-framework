# Liquid Version History

## 2.3.0 / 2011-10-16

* Several speed/memory improvements
* Numerous bug fixes
* Added support for MRI 1.9, Rubinius, and JRuby
* Added support for integer drop parameters
* Added epoch support to `date` filter
* New `raw` tag that suppresses parsing
* Added `else` option to `for` tag
* New `increment` tag
* New `split` filter


## 2.2.1 / 2010-08-23

* Added support for literal tags


## 2.2.0 / 2010-08-22

* Compatible with Ruby 1.8.7, 1.9.1 and 1.9.2-p0
* Merged some changed made by the community


## 1.9.0 / 2008-03-04

* Fixed gem install rake task
* Improve Error encapsulation in liquid by maintaining a own set of exceptions instead of relying on ruby build ins


## Before 1.9.0

* Added If with or / and expressions
* Implemented .to_liquid for all objects which can be passed to liquid like Strings Arrays Hashes Numerics and Booleans. To export new objects to liquid just implement .to_liquid on them and return objects which themselves have .to_liquid methods.
* Added more tags to standard library
* Added include tag ( like partials in rails )
* [...] Gazillion of detail improvements
* Added strainers as filter hosts for better security [Tobias Luetke]
* Fixed that rails integration would call filter with the wrong "self" [Michael Geary]
* Fixed bad error reporting when a filter called a method which doesn't exist. Liquid told you that it couldn't find the filter which was obviously misleading [Tobias Luetke]
* Removed count helper from standard lib. use size [Tobias Luetke]
* Fixed bug with string filter parameters failing to tolerate commas in strings. [Paul Hammond]
* Improved filter parameters. Filter parameters are now context sensitive; Types are resolved according to the rules of the context. Multiple parameters are now separated by the Liquid::ArgumentSeparator: , by default [Paul Hammond]
    {{ 'Typo' | link_to: 'http://typo.leetsoft.com', 'Typo - a modern weblog engine' }}
* Added Liquid::Drop. A base class which you can use for exporting proxy objects to liquid which can acquire more data when used in liquid. [Tobias Luetke]

  class ProductDrop < Liquid::Drop
    def top_sales
       Shop.current.products.find(:all, :order => 'sales', :limit => 10 )
    end
  end
  t = Liquid::Template.parse( ' {% for product in product.top_sales %} {{ product.name }} {% endfor %} '  )
  t.render('product' => ProductDrop.new )
* Added filter parameters support. Example: {{ date | format_date: "%Y" }} [Paul Hammond]
