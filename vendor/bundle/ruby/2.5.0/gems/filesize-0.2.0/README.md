## filesize
filesize.rb provides a class for easily working with file sizes.
That means:

* Parsing strings (e.g. "1 GiB") and saving it internally as bytes
* Handling both SI and binary prefixes
* Converting from any type and unit to any other (SI to SI, SI to Binary and so on)
* doing calculations with filesizes (in a smart way, see Usage for more)
* filesize.rb also provides some default sizes, like the ones of DVDs

## Usage
### Parsing a string
```ruby
Filesize.from("1 GiB")
# => #<Filesize:0x93c06c8 @bytes=1073741824, @type={:regexp=>/^([\d,.]+)?\s?(?:([kmgtpezy])i)?b$/i, :multiplier=>1024, :presuffix=>"i"}>
```

### Converting filesizes
```ruby
Filesize.from("1 GiB").to_f('KiB') # => 1048576.0
Filesize.from("1 GiB").to_f('KB')  # => 1073741.824
Filesize.from("1 GB").to_i         # => 1000000000
```

### Outputting filesizes
```ruby
Filesize.from("12502343 B").to_s('GiB') # => "0.01 GiB"
Filesize.from("12502343 B").pretty      # => "11.92 MiB"
```

### Comparing filesizes
```ruby
Filesize.from("1 KB") <=> Filesize.from("1 MB") # => -1
```

### Calculating with filesizes
#### The file size on the left side sets the type
```ruby
(Filesize.from("1400 MB")  + Filesize.from("1400 MiB")).pretty # => "2.87 GB"
(Filesize.from("1400 MiB") + Filesize.from("1400 MB")).pretty  # => "2.67 GiB"
```

#### Filesizes can also be coerced
```ruby
(Filesize.from("1400 MiB") + 1024).pretty # => "1.37 GiB"
(1024 + Filesize.from("1400 MB")).pretty  # => "1.40 GB"
```

#### filesize.rb is smart about the return value
```ruby
Filesize.from("1400 MiB") / Filesize.from("700 MiB") # => 2.0
```

#### One can also use predefined sizes
```ruby
Filesize::DVD / Filesize::CD # => 6.13566756571429
```
