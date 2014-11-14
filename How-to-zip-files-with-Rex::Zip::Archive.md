Compressing files into zip format is very easy with Metasploit. If you want, you can simply copy and paste the following into your module, and use it:

## Code:

```ruby
# Returns the compressed data in zip format
#
# @param files [Hash]
# @option files :data    [String] The file data
# @option files :fname   [String] The file path
# @option files :comment [String]
#
# @return [String] The compressed data
def zip_files(files)
  zip = Rex::Zip::Archive.new

  files.each do |f|
    data    = f[:data]
    fname   = f[:fname]
    comment = f[:comment] || ''
    zip.add_file(fname, data, comment)
  end

  zip.pack
end
```

## Usage:

```ruby
files =
  [
    {:data=>'AAAA', :fname=>'test1.txt', :comment=>'my comment'},
    {:data=>'BBBB', :fname=>'test2.txt'}
  ]

zip = zip_files(files)
```

And the above example will extract to the following:

```
$ unzip test.zip 
Archive:  test.zip
 extracting: test1.txt               
 extracting: test2.txt
```