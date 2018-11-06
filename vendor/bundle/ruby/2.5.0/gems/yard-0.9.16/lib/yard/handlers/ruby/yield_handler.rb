# frozen_string_literal: true
# Handles 'yield' calls
class YARD::Handlers::Ruby::YieldHandler < YARD::Handlers::Ruby::Base
  handles :yield, :yield0

  process do
    return unless owner.is_a?(MethodObject) # Only methods yield
    return if owner.has_tag? :yield         # Don't override yield tags
    return if owner.has_tag? :yieldparam    # Same thing.

    yieldtag = YARD::Tags::Tag.new(:yield, "", [])

    if statement.type == :yield
      statement.jump(:list).children.each do |item|
        if item == s(:var_ref, s(:kw, "self"))
          yieldtag.types << '_self'
          owner.add_tag YARD::Tags::Tag.new(:yieldparam,
            "the object that the method was called on", owner.namespace.path, '_self')
        elsif item == s(:zsuper)
          yieldtag.types << '_super'
          owner.add_tag YARD::Tags::Tag.new(:yieldparam,
            "the result of the method from the superclass", nil, '_super')
        else
          yieldtag.types << item.source
        end
      end
    end

    owner.add_tag(yieldtag) unless yieldtag.types.empty?
  end
end
