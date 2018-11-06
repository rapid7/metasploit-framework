# Rails::Dom::Testing
[![Build Status](https://travis-ci.org/rails/rails-dom-testing.svg)](https://travis-ci.org/rails/rails-dom-testing)

This gem is responsible for comparing HTML doms and asserting that DOM elements are present in Rails applications.
Doms are compared via `assert_dom_equal` and `assert_dom_not_equal`.
Elements are asserted via `assert_select`, `assert_select_encoded`, `assert_select_email` and a subset of the dom can be selected with `css_select`.
The gem is developed for Rails 4.2 and above, and will not work on previous versions.

## Deprecation warnings when upgrading to Rails 4.2:

Nokogiri is slightly more strict about the format of css selectors than the previous implementation. That's why you have warnings like:

```
DEPRECATION WARNING: The assertion was not run because of an invalid css selector.
```

Check the 4.2 release notes [section on `assert_select`](http://edgeguides.rubyonrails.org/4_2_release_notes.html#assert-select) for help.

## Installation

Add this line to your application's Gemfile:

    gem 'rails-dom-testing'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install rails-dom-testing

## Usage

### Dom Assertions

```ruby
assert_dom_equal '<h1>Lingua França</h1>', '<h1>Lingua França</h1>'

assert_dom_not_equal '<h1>Portuguese</h1>', '<h1>Danish</h1>'
```

### Selector Assertions

```ruby
# implicitly selects from the document_root_element
css_select '.hello' # => Nokogiri::XML::NodeSet of elements with hello class

# select from a supplied node. assert_select asserts elements exist.
assert_select document_root_element.at('.hello'), '.goodbye'

# elements in CDATA encoded sections can also be selected
assert_select_encoded '#out-of-your-element'

# assert elements within an html email exists
assert_select_email '#you-got-mail'
```

The documentation in [selector_assertions.rb](https://github.com/kaspth/rails-dom-testing/blob/master/lib/rails/dom/testing/assertions/selector_assertions.rb) goes into a lot more detail of how selector assertions can be used.

## Read more

Under the hood the doms are parsed with Nokogiri and you'll generally be working with these two classes:
- [`Nokogiri::XML::Node`](http://www.rubydoc.info/github/sparklemotion/nokogiri/Nokogiri/XML/Node)
- [`Nokogiri::XML::NodeSet`](http://www.rubydoc.info/github/sparklemotion/nokogiri/Nokogiri/XML/NodeSet)

Read more about Nokogiri:
- [Nokogiri](http://nokogiri.org)

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
