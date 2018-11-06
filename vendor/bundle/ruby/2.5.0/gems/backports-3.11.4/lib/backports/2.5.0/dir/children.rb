class Dir
  Backports::EXCLUDED_CHILDREN = ['.', '..'].freeze unless Backports.const_defined?('EXCLUDED_CHILDREN')
  def self.children(*args)
    entries(*args) - Backports::EXCLUDED_CHILDREN
  end
end unless Dir.respond_to? :children
