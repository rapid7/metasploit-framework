module CodeRay
module Scanners
  
  map \
    :'c++'       => :cpp,
    :cplusplus   => :cpp,
    :ecmascript  => :java_script,
    :ecma_script => :java_script,
    :rhtml       => :erb,
    :eruby       => :erb,
    :irb         => :ruby,
    :javascript  => :java_script,
    :js          => :java_script,
    :pascal      => :delphi,
    :patch       => :diff,
    :plain       => :text,
    :plaintext   => :text,
    :xhtml       => :html,
    :yml         => :yaml
  
  default :text
  
end
end
