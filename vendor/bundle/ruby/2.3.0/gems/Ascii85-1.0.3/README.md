**Status**: This project is in maintenance mode. I will not develop new features, but I will address Issues and Pull Requests.

# Ascii85

[![Build Status](https://travis-ci.org/DataWraith/ascii85gem.svg?branch=master)](https://travis-ci.org/DataWraith/ascii85gem)

## Description

Ascii85 is a simple gem that provides methods for encoding/decoding Adobe's
binary-to-text encoding of the same name.

See http://www.adobe.com/products/postscript/pdfs/PLRM.pdf page 131 and
http://en.wikipedia.org/wiki/Ascii85 for more information about the format.


## Installation

`sudo gem install Ascii85`


## Usage

```
require 'rubygems'
require 'ascii85'

Ascii85.encode("Ruby")
=> "<~;KZGo~>"

Ascii85.decode("<~;KZGo~>")
=> "Ruby"
```

In addition, Ascii85.encode can take a second parameter that specifies the
length of the returned lines. The default is 80; use `false` for unlimited.

Ascii85.decode expects the input to be enclosed in <~ and ~> — it
ignores everything outside of these. The output of Ascii85.decode
will have the ASCII-8BIT encoding, so in Ruby 1.9 you may have to use
<tt>String#force_encoding</tt> to correct the encoding.


## Command-line utility

This gem includes `ascii85`, a command-line utility modeled after `base64` from
the GNU coreutils. It can be used to encode/decode Ascii85 directly from the
command-line:

```
Usage: ascii85 [OPTIONS] [FILE]
Encodes or decodes FILE or STDIN using Ascii85 and writes to STDOUT.
    -w, --wrap COLUMN                Wrap lines at COLUMN. Default is 80, use 0 for no wrapping
    -d, --decode                     Decode the input
    -h, --help                       Display this help and exit
        --version                    Output version information
```


## License

Ascii85 is distributed under the MIT License. See the accompanying LICENSE file
for details.
