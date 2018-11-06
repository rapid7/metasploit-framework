class Hash
  # Standard in rails. See official documentation[http://api.rubyonrails.org/classes/ActiveSupport/CoreExtensions/Hash/Keys.html]
  def reverse_merge(other_hash)
    other_hash.merge(self)
  end unless method_defined? :reverse_merge

  # Standard in rails. See official documentation[http://api.rubyonrails.org/classes/ActiveSupport/CoreExtensions/Hash/Keys.html]
  def reverse_merge!(other_hash)
    replace(reverse_merge(other_hash))
  end unless method_defined? :reverse_merge!

  # Standard in rails. See official documentation[http://api.rubyonrails.org/classes/ActiveSupport/CoreExtensions/Hash/Keys.html]
  def symbolize_keys
    Hash[map{|key,value| [(key.to_sym rescue key) || key, value] }]
  end unless method_defined? :symbolize_keys

  # Standard in rails. See official documentation[http://api.rubyonrails.org/classes/ActiveSupport/CoreExtensions/Hash/Keys.html]
  def symbolize_keys!
    self.replace(self.symbolize_keys)
  end unless method_defined? :symbolize_keys!

  # Standard in rails. See official documentation[http://api.rubyonrails.org/classes/ActiveSupport/CoreExtensions/Hash/Keys.html]
  def stringify_keys
    Hash[map{|key,value| [key.to_s, value] }]
  end unless method_defined? :stringify_keys

  # Standard in rails. See official documentation[http://api.rubyonrails.org/classes/ActiveSupport/CoreExtensions/Hash/Keys.html]
  def stringify_keys!
    self.replace(self.stringify_keys)
  end unless method_defined? :stringify_keys!
end
