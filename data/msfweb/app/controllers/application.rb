# Filters added to this controller will be run for all controllers in the application.
# Likewise, all the methods added will be available for all controllers.
class ApplicationController < ActionController::Base

  def search_modules(mlist, terms)
    res = []
    
    unless terms
      return nil
    end
    
    mlist.each do |m|
	  
      if (m.name.downcase.index(terms.downcase))
        res << m
        next
      end

      if (m.description.downcase.index(terms.downcase))
        res << m
        next
      end
            
    end
	
	p res.length
	
    res
  end
  
end
