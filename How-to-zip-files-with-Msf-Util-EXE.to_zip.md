# How to zip files with Msf::Util::EXE.to_zip
Compressing files into zip format is very easy with Metasploit. For most purposes, you can use `Msf::Util::EXE.to_zip()` to compress data into a zip file.

Note that the former `Rex::Zip::Archive()` should no longer be used.

## Usage:

```ruby
files =
  [
    {data: 'AAAA', fname: 'test1.txt', comment: 'my comment'},
    {data: 'BBBB', fname: 'test2.txt'}
  ]

zip = Msf::Util::EXE.to_zip(files)
```

If saved as a file, the above example will extract to the following:

```
$ unzip test.zip 
Archive:  test.zip
 extracting: test1.txt               
 extracting: test2.txt
```