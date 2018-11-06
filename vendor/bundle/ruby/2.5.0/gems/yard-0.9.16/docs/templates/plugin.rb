# frozen_string_literal: true
include YARD
include Templates

module TagTemplateHelper
  def all_tags
    Registry.all(:method).map {|m| m.tag('yard.tag') }.compact
  end

  def all_directives
    Registry.all(:method).map {|m| m.tag('yard.directive') }.compact
  end

  def collect_tags
    (all_tags + all_directives).sort_by(&:name)
  end

  def tag_link(tag)
    link_file("docs/Tags.md", tag_link_name(tag), tag.name)
  end

  def tag_link_name(tag)
    prefix = tag.tag_name == 'yard.directive' ? '@!' : '@'
    h(prefix + tag.name)
  end

  # Wrap url_for and url_for_file to rewrite object when generating docs for
  # yard.tag/directive objects.
  %w(url_for url_for_file).each do |meth|
    self.class.send(:define_method, meth) do
      if object.is_a?(CodeObjects::Base) &&
         (object.tag('yard.tag') || object.tag('yard.directive') ||
         (object.type == :class && object.superclass.name == :Directive))
        obj = object
        self.object = Registry.root
        url = super
        self.object = obj
        url
      else
        super
      end
    end
  end

  def linkify(*args)
    if args.first.is_a?(String)
      case args.first
      when "yard:include_tags"
        return T('yard_tags').run(options)
      when /^tag:(\S+)/
        tag_name = $1
        suffix = "tag"
        if tag_name =~ /^!/
          tag_name = tag_name[1..-1]
          suffix = "directive"
        end

        obj = Registry.at("YARD::Tags::Library##{tag_name}_#{suffix}")
        return tag_link(obj.tag("yard.#{suffix}")) if obj

        log.warn "Cannot find tag: #{args.first}"
        return args.first
      end
    end
    super
  end
end

Template.extra_includes << TagTemplateHelper
Engine.register_template_path(File.dirname(__FILE__))
