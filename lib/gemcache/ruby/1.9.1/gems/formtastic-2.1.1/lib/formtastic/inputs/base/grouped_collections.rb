module Formtastic
  module Inputs
    module Base
      module GroupedCollections
      
        def raw_grouped_collection
          @raw_grouped_collection ||= raw_collection.map { |option| option.send(options[:group_by]) }.uniq
        end
      
        def grouped_collection
          @grouped_collection ||= raw_grouped_collection.sort_by { |group_item| group_item.send(group_label_method) }
        end
      
        def group_label_method
          @group_label_method ||= (group_label_method_from_options || group_label_method_from_grouped_collection)
        end
      
        def group_label_method_from_options
          options[:group_label]
        end
      
        def group_label_method_from_grouped_collection
          label_and_value_method_from_collection(raw_grouped_collection).first
        end
      
        def group_association
          @group_association ||= (group_association_from_options || group_association_from_reflection)
        end
      
        def group_association_from_options
          options[:group_association]
        end
      
        def group_by
          options[:group_by]
        end
      
        def group_association_from_reflection
          method_to_group_association_by = reflection.klass.reflect_on_association(group_by)
          group_class = method_to_group_association_by.klass
      
          # This will return in the normal case
          return method.to_s.pluralize.to_sym if group_class.reflect_on_association(method.to_s.pluralize)
      
          # This is for belongs_to associations named differently than their class
          # form.input :parent, :group_by => :customer
          # eg.
          # class Project
          #   belongs_to :parent, :class_name => 'Project', :foreign_key => 'parent_id'
          #   belongs_to :customer
          # end
          # class Customer
          #   has_many :projects
          # end
          group_method = group_class.to_s.underscore.pluralize.to_sym
          return group_method if group_class.reflect_on_association(group_method) # :projects
      
          # This is for has_many associations named differently than their class
          # eg.
          # class Project
          #   belongs_to :parent, :class_name => 'Project', :foreign_key => 'parent_id'
          #   belongs_to :customer
          # end
          # class Customer
          #   has_many :tasks, :class_name => 'Project', :foreign_key => 'customer_id'
          # end
          possible_associations = group_class.reflect_on_all_associations(:has_many).find_all {|assoc| assoc.klass == reflection.klass }
          return possible_associations.first.name.to_sym if possible_associations.count == 1
      
          raise "Cannot infer group association for #{method} grouped by #{group_by}, there were #{possible_associations.empty? ? 'no' : possible_associations.size} possible associations. Please specify using :group_association"
        end

      end
    end
  end
end
      