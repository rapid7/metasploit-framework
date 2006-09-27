# Filters added to this controller will be run for all controllers in the application.
# Likewise, all the methods added will be available for all controllers.
class ApplicationController < ActionController::Base

  def search_modules(mlist, terms)
    res = []
    mlist.each do |m|
      
      if (m.name.downcase.index(terms.downcase))
        res << m
        next
      end

      if (m.desc.downcase.index(terms.downcase))
        res << m
        next
      end
            
    end
    res
  end
  
end
