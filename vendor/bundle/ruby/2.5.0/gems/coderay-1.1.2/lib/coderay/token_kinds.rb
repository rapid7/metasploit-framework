module CodeRay
  
  # A Hash of all known token kinds and their associated CSS classes.
  TokenKinds = Hash.new(false)
  
  # speedup
  TokenKinds.compare_by_identity if TokenKinds.respond_to? :compare_by_identity
  
  TokenKinds.update(  # :nodoc:
    :debug               => 'debug',              # highlight for debugging (white on blue background)
    
    :annotation          => 'annotation',         # Groovy, Java
    :attribute_name      => 'attribute-name',     # HTML, CSS
    :attribute_value     => 'attribute-value',    # HTML
    :binary              => 'binary',             # Python, Ruby
    :char                => 'char',               # most scanners, also inside of strings
    :class               => 'class',              # lots of scanners, for different purposes also in CSS
    :class_variable      => 'class-variable',     # Ruby, YAML
    :color               => 'color',              # CSS
    :comment             => 'comment',            # most scanners
    :constant            => 'constant',           # PHP, Ruby
    :content             => 'content',            # inside of strings, most scanners
    :decorator           => 'decorator',          # Python
    :definition          => 'definition',         # CSS
    :delimiter           => 'delimiter',          # inside strings, comments and other types
    :directive           => 'directive',          # lots of scanners
    :doctype             => 'doctype',            # Goorvy, HTML, Ruby, YAML
    :docstring           => 'docstring',          # Python
    :done                => 'done',               # Taskpaper
    :entity              => 'entity',             # HTML
    :error               => 'error',              # invalid token, most scanners
    :escape              => 'escape',             # Ruby (string inline variables like #$foo, #@bar)
    :exception           => 'exception',          # Java, PHP, Python
    :filename            => 'filename',           # Diff
    :float               => 'float',              # most scanners
    :function            => 'function',           # CSS, JavaScript, PHP
    :global_variable     => 'global-variable',    # Ruby, YAML
    :hex                 => 'hex',                # hexadecimal number; lots of scanners
    :id                  => 'id',                 # CSS
    :imaginary           => 'imaginary',          # Python
    :important           => 'important',          # CSS, Taskpaper
    :include             => 'include',            # C, Groovy, Java, Python, Sass
    :inline              => 'inline',             # nested code, eg. inline string evaluation; lots of scanners
    :inline_delimiter    => 'inline-delimiter',   # used instead of :inline > :delimiter FIXME: Why use inline_delimiter?
    :instance_variable   => 'instance-variable',  # Ruby
    :integer             => 'integer',            # most scanners
    :key                 => 'key',                # lots of scanners, used together with :value
    :keyword             => 'keyword',            # reserved word that's actually implemented; most scanners
    :label               => 'label',              # C, PHP
    :local_variable      => 'local-variable',     # local and magic variables; some scanners
    :map                 => 'map',                # Lua tables
    :modifier            => 'modifier',           # used inside on strings; lots of scanners
    :namespace           => 'namespace',          # Clojure, Java, Taskpaper
    :octal               => 'octal',              # lots of scanners
    :predefined          => 'predefined',         # predefined function: lots of scanners
    :predefined_constant => 'predefined-constant',# lots of scanners
    :predefined_type     => 'predefined-type',    # C, Java, PHP
    :preprocessor        => 'preprocessor',       # C, Delphi, HTML
    :pseudo_class        => 'pseudo-class',       # CSS
    :regexp              => 'regexp',             # Groovy, JavaScript, Ruby
    :reserved            => 'reserved',           # most scanners
    :shell               => 'shell',              # Ruby
    :string              => 'string',             # most scanners
    :symbol              => 'symbol',             # Clojure, Ruby, YAML
    :tag                 => 'tag',                # CSS, HTML
    :type                => 'type',               # CSS, Java, SQL, YAML
    :value               => 'value',              # used together with :key; CSS, JSON, YAML
    :variable            => 'variable',           # Sass, SQL, YAML
    
    :change              => 'change',             # Diff
    :delete              => 'delete',             # Diff
    :head                => 'head',               # Diff, YAML
    :insert              => 'insert',             # Diff
    :eyecatcher          => 'eyecatcher',         # Diff
    
    :ident               => false,                # almost all scanners
    :operator            => false,                # almost all scanners
    
    :space               => false,                # almost all scanners
    :plain               => false                 # almost all scanners
  )
  
  TokenKinds[:method]  = TokenKinds[:function]
  TokenKinds[:unknown] = TokenKinds[:plain]
end
