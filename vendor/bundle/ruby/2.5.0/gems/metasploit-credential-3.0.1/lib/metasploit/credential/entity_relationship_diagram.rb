require 'rails_erd/diagram/graphviz'

# @todo Extract (along with MetasploitDataModel::EntityRelationshipDiagram), common ERD code and move to metasploit-documentation or metasploit-entity_relationship_diagram
module Metasploit::Credential::EntityRelationshipDiagram
  #
  # CONSTANTS
  #

  # Enable all attributes
  ATTRIBUTES = [
      :content,
      :foreign_keys,
      :primary_keys,
      :timestamps
  ]

  # Only show direct relationships since the ERD is for use with SQL and there is no need to show has_many :through
  # for those purposes.
  INDIRECT = false

  # Show inheritance for Single-Table Inheritance
  INHERITANCE = true

  # Use crowsfoot notation since its what we use for manually drawn diagrams.
  NOTATION = :crowsfoot

  # Default options for Diagram.
  DEFAULT_OPTIONS = {
      attributes: ATTRIBUTES,
      indirect: INDIRECT,
      inheritance: INHERITANCE,
      notation: NOTATION
  }

  #
  # Class Methods
  #

  # All {cluster clusters} of classes that are reachable through belongs_to from each ActiveRecord::Base descendant
  #
  # @return [Hash{Class<ActiveRecord::Base> => Set<Class<ActiveRecord::Base>>}] Maps entry point to cluster to its
  #   cluster.
  def self.cluster_by_class
    cluster_by_class = {}

    Metasploit::Credential::Engine.instance.eager_load!

    ActiveRecord::Base.descendants.each do |klass|
      klass_cluster = cluster(klass)
      cluster_by_class[klass] = klass_cluster
    end

    cluster_by_class
  end

  # Cluster of classes that are reachable through belongs_to from `classes`.
  #
  # @param classes [Array<Class<ActiveRecord::Base>>] classes that must be in cluster.  All other classes in the
  #   returned cluster will be classes to which `classes` belong directly or indirectly.
  # @return [Set<Class<ActiveRecord::Base>>]
  def self.cluster(*classes)
    class_queue = classes.dup
    visited_class_set = Set.new

    until class_queue.empty?
      klass = class_queue.pop
      # add immediately to visited set in case there are recursive associations
      visited_class_set.add klass

      # only iterate belongs_to as they need to be included so that foreign keys aren't let dangling in the ERD.
      reflections = klass.reflect_on_all_associations(:belongs_to)

      reflections.each do |reflection|
        if reflection.options[:polymorphic]
          target_klasses = polymorphic_classes(reflection)
        else
          target_klasses = [reflection.klass]
        end

        target_klasses.each do |target_klass|
          unless visited_class_set.include? target_klass
            class_queue << target_klass
          end
        end
      end
    end

    visited_class_set
  end

  # Creates Graphviz diagram.
  #
  # @param options [Hash{Symbol => Object}]
  # @option options [RailsERD::Domain] :domain ({domain}) The domain to diagram.
  # @option options [String] :filename name of file (without extension) to which to write diagram.
  # @option options [String] :title Title of the diagram to include on the diagram.
  # @return [String] path where diagram was written.
  def self.create(options={})
    domain = options[:domain]
    domain ||= self.domain

    diagram_options = options.except(:domain)
    merged_diagram_options = DEFAULT_OPTIONS.merge(diagram_options)

    require 'rails_erd/domain'
    diagram = RailsERD::Diagram::Graphviz.new(domain, merged_diagram_options)
    path = diagram.create

    path
  end


  # Domain containing all models in this gem.
  #
  # @return [RailsERD::Domain]
  def self.domain
    require_models

    require 'rails_erd/domain'
    RailsERD::Domain.generate
  end

  # Set of largest clusters from {cluster_by_class}.
  #
  # @return [Array<Set<Class<ActiveRecord::Base>>>]
  def self.maximal_clusters
    clusters = cluster_by_class.values
    unique_clusters = clusters.uniq

    maximal_clusters = unique_clusters.dup
    cluster_queue = unique_clusters.dup

    until cluster_queue.empty?
      cluster = cluster_queue.pop

      proper_subset = false

      maximal_clusters.each do |maximal_cluster|
        if cluster.proper_subset? maximal_cluster
          proper_subset = true
          break
        end
      end

      if proper_subset
        maximal_clusters.delete(cluster)
      end
    end

    maximal_clusters
  end

  # Calculates the target classes for a polymorphic `belongs_to`.
  #
  # @return [Array<ActiveRecord::Base>]
  def self.polymorphic_classes(belongs_to_reflection)
    name = belongs_to_reflection.name

    ActiveRecord::Base.descendants.each_with_object([]) { |descendant, target_classes|
      has_many_reflections = descendant.reflect_on_all_associations(:has_many)

      has_many_reflections.each do |has_many_reflection|
        as = has_many_reflection.options[:as]

        if as == name
          target_classes << descendant
        end
      end
    }
  end
end