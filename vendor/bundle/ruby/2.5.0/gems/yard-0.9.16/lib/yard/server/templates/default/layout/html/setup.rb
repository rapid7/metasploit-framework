# frozen_string_literal: true
def javascripts
  super + %w(js/autocomplete.js)
end

def stylesheets
  super + %w(css/custom.css)
end
