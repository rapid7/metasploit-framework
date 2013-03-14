module Liquid

  # A drop in liquid is a class which allows you to export DOM like things to liquid.
  # Methods of drops are callable.
  # The main use for liquid drops is the implement lazy loaded objects.
  # If you would like to make data available to the web designers which you don't want loaded unless needed then
  # a drop is a great way to do that
  #
  # Example:
  #
  #   class ProductDrop < Liquid::Drop
  #     def top_sales
  #       Shop.current.products.find(:all, :order => 'sales', :limit => 10 )
  #     end
  #   end
  #
  #   tmpl = Liquid::Template.parse( ' {% for product in product.top_sales %} {{ product.name }} {%endfor%} '  )
  #   tmpl.render('product' => ProductDrop.new ) # will invoke top_sales query.
  #
  # Your drop can either implement the methods sans any parameters or implement the before_method(name) method which is a
  # catch all
  class Drop
    attr_writer :context

    # Catch all for the method
    def before_method(method)
      nil
    end

    # called by liquid to invoke a drop
    def invoke_drop(method_or_key)
      if method_or_key && method_or_key != '' && self.class.public_method_defined?(method_or_key.to_s.to_sym)
        send(method_or_key.to_s.to_sym)
      else
        before_method(method_or_key)
      end
    end

    def has_key?(name)
      true
    end

    def to_liquid
      self
    end

    alias :[] :invoke_drop
  end
end
