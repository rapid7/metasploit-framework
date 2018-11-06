module CodeRay
module Scanners
  
  class Taskpaper < Scanner
    
    register_for :taskpaper
    file_extension 'taskpaper'
    
  protected
    
    def scan_tokens encoder, options
      until eos?
        if match = scan(/\S.*:.*$/)                  # project
          encoder.text_token(match, :namespace)
        elsif match = scan(/-.+@done.*/)             # completed task
          encoder.text_token(match, :done)
        elsif match = scan(/-(?:[^@\n]+|@(?!due))*/) # task
          encoder.text_token(match, :plain)
        elsif match = scan(/@due.*/)                 # comment
          encoder.text_token(match, :important)
        elsif match = scan(/.+/)                     # comment
          encoder.text_token(match, :comment)
        elsif match = scan(/\s+/)                    # space
          encoder.text_token(match, :space)
        else                                         # other
          encoder.text_token getch, :error
        end
      end
      
      encoder
    end
    
  end
  
end
end
