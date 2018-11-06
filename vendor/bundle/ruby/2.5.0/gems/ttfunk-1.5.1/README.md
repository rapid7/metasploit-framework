# TTFunk

![Maintained: yes](https://img.shields.io/badge/maintained-yes-brightgreen.png)

TTFunk is a TrueType font parser written in pure ruby.

## Installation

The recommended installation method is via Rubygems.

    gem install ttfunk

## Usage

Basic usage:

    require 'ttfunk'

    file = TTFunk::File.open("some/path/myfont.ttf")
    puts "name    : #{file.name.font_name.join(', ')}"
    puts "ascent  : #{file.ascent}"
    puts "descent : #{file.descent}"

For more detailed examples, explore the examples directory.

## Licensing

Matz's terms for Ruby, GPLv2, or GPLv3. See LICENSE for details.

##  Authorship

This project is maintained by the same folks who run the Prawn PDF project.

You can find the full list of Github users who have at least one patch accepted
to ttfunk at:

  https://github.com/prawnpdf/ttfunk/contributors

## Mailing List

TTFunk is maintained as a dependency of Prawn, the ruby PDF generation library.

Any questions or feedback should be sent to the Prawn google group.

https://groups.google.com/group/prawn-ruby
