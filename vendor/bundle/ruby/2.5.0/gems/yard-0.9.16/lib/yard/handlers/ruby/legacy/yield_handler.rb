# frozen_string_literal: true
# (see Ruby::YieldHandler)
class YARD::Handlers::Ruby::Legacy::YieldHandler < YARD::Handlers::Ruby::Legacy::Base
  handles TkYIELD

  process do
    return unless owner.is_a?(MethodObject) # Only methods yield
    return if owner.has_tag? :yield         # Don't override yield tags
    return if owner.has_tag? :yieldparam    # Same thing.

    yieldtag = YARD::Tags::Tag.new(:yield, "", [])
    tokval_list(statement.tokens[2..-1], Token).each do |item|
      item = item.inspect unless item.is_a?(String)
      if item == "self"
        yieldtag.types << '_self'
        owner.add_tag YARD::Tags::Tag.new(:yieldparam,
          "the object that the method was called on", owner.namespace.path, '_self')
      elsif item == "super"
        yieldtag.types << '_super'
        owner.add_tag YARD::Tags::Tag.new(:yieldparam,
          "the result of the method from the superclass", nil, '_super')
      else
        yieldtag.types << item
      end
    end

    owner.add_tag(yieldtag) unless yieldtag.types.empty?
  end
end
