module CodeRay
  
  # A Hash of all known token kinds and their associated CSS classes.
  TokenKinds = Hash.new do |h, k|
    warn 'Undefined Token kind: %p' % [k] if $CODERAY_DEBUG
    false
  end
  
  # speedup
  TokenKinds.compare_by_identity if TokenKinds.respond_to? :compare_by_identity
  
  TokenKinds.update(  # :nodoc:
    :annotation          => 'annotation',
    :attribute_name      => 'attribute-name',
    :attribute_value     => 'attribute-value',
    :binary              => 'bin',
    :char                => 'char',
    :class               => 'class',
    :class_variable      => 'class-variable',
    :color               => 'color',
    :comment             => 'comment',
    :complex             => 'complex',
    :constant            => 'constant',
    :content             => 'content',
    :debug               => 'debug',
    :decorator           => 'decorator',
    :definition          => 'definition',
    :delimiter           => 'delimiter',
    :directive           => 'directive',
    :doc                 => 'doc',
    :doctype             => 'doctype',
    :doc_string          => 'doc-string',
    :entity              => 'entity',
    :error               => 'error',
    :escape              => 'escape',
    :exception           => 'exception',
    :filename            => 'filename',
    :float               => 'float',
    :function            => 'function',
    :global_variable     => 'global-variable',
    :hex                 => 'hex',
    :imaginary           => 'imaginary',
    :important           => 'important',
    :include             => 'include',
    :inline              => 'inline',
    :inline_delimiter    => 'inline-delimiter',
    :instance_variable   => 'instance-variable',
    :integer             => 'integer',
    :key                 => 'key',
    :keyword             => 'keyword',
    :label               => 'label',
    :local_variable      => 'local-variable',
    :modifier            => 'modifier',
    :namespace           => 'namespace',
    :octal               => 'octal',
    :predefined          => 'predefined',
    :predefined_constant => 'predefined-constant',
    :predefined_type     => 'predefined-type',
    :preprocessor        => 'preprocessor',
    :pseudo_class        => 'pseudo-class',
    :regexp              => 'regexp',
    :reserved            => 'reserved',
    :shell               => 'shell',
    :string              => 'string',
    :symbol              => 'symbol',
    :tag                 => 'tag',
    :type                => 'type',
    :value               => 'value',
    :variable            => 'variable',
    
    :change              => 'change',
    :delete              => 'delete',
    :head                => 'head',
    :insert              => 'insert',
    
    :eyecatcher          => 'eyecatcher',
    
    :ident               => false,
    :operator            => false,
    
    :space               => false,
    :plain               => false
  )
  
  TokenKinds[:method]    = TokenKinds[:function]
  TokenKinds[:escape]    = TokenKinds[:delimiter]
  TokenKinds[:docstring] = TokenKinds[:comment]
  
  TokenKinds.freeze
end
