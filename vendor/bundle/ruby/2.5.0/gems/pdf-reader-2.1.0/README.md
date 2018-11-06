# Release Notes

The PDF::Reader library implements a PDF parser conforming as much as possible
to the PDF specification from Adobe.

It provides programmatic access to the contents of a PDF file with a high
degree of flexibility.

The PDF 1.7 specification is a weighty document and not all aspects are
currently supported. I welcome submission of PDF files that exhibit
unsupported aspects of the spec to assist with improving our support.

This is primarily a low-level library that should be used as the foundation for
higher level functionality - it's not going to render a PDF for you. There are
a few exceptions to support very common use cases like extracting text from a
page.

# Installation

The recommended installation method is via Rubygems.

```ruby
  gem install pdf-reader
```

# Usage

Begin by creating a PDF::Reader instance that points to a PDF file. Document
level information (metadata, page count, bookmarks, etc) is available via
this object.

```ruby
    reader = PDF::Reader.new("somefile.pdf")

    puts reader.pdf_version
    puts reader.info
    puts reader.metadata
    puts reader.page_count
 ```

PDF::Reader.new accepts an IO stream or a filename. Here's an example with
an IO stream:

```ruby
    require 'open-uri'

    io     = open('http://example.com/somefile.pdf')
    reader = PDF::Reader.new(io)
    puts reader.info
 ```

If you open a PDF with File#open or IO#open, I strongly recommend using "rb"
mode to ensure the file isn't mangled by ruby being 'helpful'. This is
particularly important on windows and MRI >= 1.9.2.

```ruby
    File.open("somefile.pdf", "rb") do |io|
      reader = PDF::Reader.new(io)
      puts reader.info
    end
 ```

PDF is a page based file format, so most visible information is available via
page-based iteration

```ruby
    reader = PDF::Reader.new("somefile.pdf")

    reader.pages.each do |page|
      puts page.fonts
      puts page.text
      puts page.raw_content
    end
```

If you need to access the full program for rendering a page, use the walk() method
of PDF::Reader::Page.

```ruby
    class RedGreenBlue
      def set_rgb_color_for_nonstroking(r, g, b)
        puts "R: #{r}, G: #{g}, B: #{b}"
      end
    end

    reader   = PDF::Reader.new("somefile.pdf")
    page     = reader.page(1)
    receiver = RedGreenBlue.new
    page.walk(receiver)
```

For low level access to the objects in a PDF file, use the ObjectHash class like
so:

```ruby
    reader  = PDF::Reader.new("somefile.pdf")
    puts reader.objects.inspect
```

# Text Encoding

Regardless of the internal encoding used in the PDF all text will be converted
to UTF-8 before it is passed back from PDF::Reader.

Strings that contain binary data (like font blobs) will be marked as such.

# Former API

Version 1.0.0 of PDF::Reader introduced a new page-based API that provides
efficient and easy access to any page.

The pre-1.0 API was deprecated during the 1.x release series, and has been
removed from 2.0.0.

# Exceptions

There are two key exceptions that you will need to watch out for when processing a
PDF file:

MalformedPDFError - The PDF appears to be corrupt in some way. If you believe the
file should be valid, or that a corrupt file didn't raise an exception, please
forward a copy of the file to the maintainers (preferably via the google group)
and we will attempt to improve the code.

UnsupportedFeatureError - The PDF uses a feature that PDF::Reader doesn't currently
support. Again, we welcome submissions of PDF files that exhibit these features to help
us with future code improvements.

MalformedPDFError has some subclasses if you want to detect finer grained issues. If you
don't, 'rescue MalformedPDFError' will catch all the subclassed errors as well.

Any other exceptions should be considered bugs in either PDF::Reader (please
report it!).

# PDF Integrity

Windows developers may run into problems when running specs due to MalformedPDFError's
This is usually because CRLF characters are automatically added to some of the PDF's in
the spec folder when you checkout a branch from Git.

To remove any invalid CRLF characters added while checking out a branch from Git, run:

```ruby
    rake fix_integrity
```

# Maintainers

* James Healy <mailto:jimmy@deefa.com>

# Licensing

This library is distributed under the terms of the MIT License. See the included file for
more detail.

# Mailing List

Any questions or feedback should be sent to the PDF::Reader google group. It's
better that any answers be available for others instead of hiding in someone's
inbox.

http://groups.google.com/group/pdf-reader

# Examples

The easiest way to explain how this works in practice is to show some examples.
Check out the examples/ directory for a few files.

# Known Limitations

Occasionally some text cannot be extracted properly due to the way it has been
stored, or the use of invalid bytes. In these cases PDF::Reader will output a
little UTF-8 friendly box to indicate an unrecognisable character.

# Resources

* PDF::Reader Code Repository: http://github.com/yob/pdf-reader

* PDF Specification: http://www.adobe.com/devnet/pdf/pdf_reference.html

* PDF Tutorial Slide Presentations: http://home.comcast.net/~jk05/presentations/PDFTutorials.html

* Developing with PDF (book): http://shop.oreilly.com/product/0636920025269.do
