# frozen_string_literal: true
def init
  sections :header, [T('docstring')]
end

def format_args(object)
  return if object.parameters.nil?
  params = object.parameters
  if object.has_tag?(:yield) || object.has_tag?(:yieldparam)
    params.reject! do |param|
      param[0].to_s[0, 1] == "&" &&
        !object.tags(:param).any? {|t| t.name == param[0][1..-1] }
    end
  end

  if params.empty?
    ""
  else
    args = params.map {|n, v| v ? "<em>#{h n}</em> = #{h v}" : "<em>" + n.to_s + "</em>" }.join(", ")
    args
  end
end
