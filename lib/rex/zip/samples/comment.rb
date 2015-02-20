# -*- coding: binary -*-

#
# Create a zip file with comments!
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
inc = File.dirname(msfbase) + '/../../..'
$:.unshift(inc)

require 'rex/zip'

# example usage
zip = Rex::Zip::Archive.new
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
