#!/usr/bin/env ruby

#
# Create a zip file with comments!
#

require 'zip'

# example usage
zip = Zip::Archive.new
zip.add_file("elite.txt", "A" * 1024, nil, %Q<
                                 +---------------+
                                 | file comment! |
                                 +---------------+
>)
zip.set_comment(%Q<

+------------------------------------------+
|                                          |
| Hello!  This is the Zip Archive comment! |
|                                          |
+------------------------------------------+

>)
zip.save_to("lolz.zip")
