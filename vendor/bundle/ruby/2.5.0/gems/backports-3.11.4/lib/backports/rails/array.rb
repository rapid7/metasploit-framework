class Array
  # See official documentation[http://api.rubyonrails.org/classes/ActiveSupport/CoreExtensions/Array/ExtractOptions.html]
  def extract_options!
    last.is_a?(::Hash) ? pop : {}
  end unless method_defined? :extract_options!
end
