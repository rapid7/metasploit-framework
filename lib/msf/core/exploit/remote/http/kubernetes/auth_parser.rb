# -*- coding: binary -*-

# Parses the succinct Kubernetes authentication API response and converts it into
# a more consumable format
class Msf::Exploit::Remote::HTTP::Kubernetes::AuthParser
  def initialize(auth_response)
    @auth_response = auth_response
  end

  # Extracts the list of rules associated with a kubernetes auth response
  def rules
    resource_rules = auth_response.dig(:status, :resourceRules) || []
    non_resource_rules = auth_response.dig(:status, :nonResourceRules) || []
    policy_rules = resource_rules + non_resource_rules

    broke_down_policy_rules = policy_rules.flat_map do |policy_rule|
      breakdown_policy_rule(policy_rule)
    end
    compacted_rules = compact_policy_rules(broke_down_policy_rules)
    sorted_rules = compacted_rules.sort_by { |rule| human_readable_policy_rule(rule) }

    sorted_rules
  end

  # Converts the kubernetes auth response into an array of human readable table
  def as_table
    columns = ['Resources', 'Non-Resource URLs', 'Resource Names', 'Verbs']
    rows = rules.map do |rule|
      [
        combine_resource_groups(rule[:resources], rule[:apiGroups]),
        "[#{rule[:nonResourceURLs].join(' ')}]",
        "[#{rule[:resourceNames].join(' ')}]",
        "[#{rule[:verbs].join(' ')}]"
      ]
    end

    { columns: columns, rows: rows }
  end

  protected

  attr :auth_response

  def policy_rule_for(apiGroups: [], resources: [], verbs: [], resourceNames: [], nonResourceURLs: [])
    {
      apiGroups: apiGroups,
      resources: resources,
      verbs: verbs,
      resourceNames: resourceNames,
      nonResourceURLs: nonResourceURLs
    }
  end

  # Converts the original policy rule into its smaller policy rules, where
  # there is at most one verb for each rule
  def breakdown_policy_rule(policy_rule)
    sub_rules = []
    policy_rule.fetch(:apiGroups, []).each do |group|
      policy_rule.fetch(:resources, []).each do |resource|
        policy_rule.fetch(:verbs, []).each do |verb|
          if policy_rule.fetch(:resourceNames, []).any?
            sub_rules += policy_rule[:resourceNames].map do |resource_name|
              policy_rule_for(
                apiGroups: [group],
                resources: [resource],
                verbs: [verb],
                resourceNames: [resource_name]
              )
            end
          else
            sub_rules << policy_rule_for(
              apiGroups: [group],
              resources: [resource],
              verbs: [verb]
            )
          end
        end
      end
    end

    sub_rules += policy_rule.fetch(:nonResourceURLs, []).flat_map do |non_resource_url|
      policy_rule[:verbs].map do |verb|
        policy_rule_for(
          nonResourceURLs: [non_resource_url],
          verbs: [verb]
        )
      end
    end

    sub_rules
  end

  # Finds the original policy rule associated with a simplified rule
  def find_policy(existing_simple_rules, simple_rule)
    return nil if simple_rule.nil?

    existing_simple_rules.each do |existing_simple_rule, policy|
      is_match = (
        existing_simple_rule[:group] == simple_rule[:group] &&
          existing_simple_rule[:resource] == simple_rule[:resource] &&
          existing_simple_rule[:resourceName] == simple_rule[:resourceName]
      )

      if is_match
        return policy
      end
    end

    nil
  end

  # Merge policy rules together, by joining rules that are associated with the same resource, but different
  # verbs
  def compact_policy_rules(policy_rules)
    compact_rules = []
    simple_rules = {}
    policy_rules.each do |policy_rule|
      simple_rule = as_simple_rule(policy_rule)
      if simple_rule
        existing_rule = find_policy(simple_rules, simple_rule)

        if existing_rule
          existing_rule[:verbs] ||= []
          existing_rule[:verbs] = (existing_rule[:verbs] + policy_rule[:verbs]).uniq
        else
          simple_rules[simple_rule] = policy_rule.clone
        end
      else
        compact_rules << policy_rule
      end
    end

    compact_rules += simple_rules.values
    compact_rules
  end

  # returns nil if it's not possible to simplify this rule
  def as_simple_rule(policy_rule)
    return nil if policy_rule[:resourceNames].count > 1 || policy_rule[:nonResourceURLs].count > 0
    return nil if policy_rule[:apiGroups].count != 1 || policy_rule[:resources].count != 1

    allowed_keys = %i[apiGroups resources verbs resourceNames nonResourceURLs]
    unsupported_keys = policy_rule.keys - allowed_keys
    return nil if unsupported_keys.any?

    simple_rule = {
      group: policy_rule[:apiGroups][0],
      resource: policy_rule[:resources][0]
    }

    if policy_rule[:resourceNames].any?
      simple_rule.merge(
        {
          resourceName: policy_rule[:resourceNames][0]
        }
      )
    end

    simple_rule
  end

  def human_readable_policy_rule(rule)
    parts = []

    parts << "APIGroups:[#{rule[:apiGroups].join(' ')}]" if rule[:apiGroups].any?
    parts << "Resources:[#{rule[:resources].join(' ')}]" if rule[:resources].any?
    parts << "NonResourceURLs:[#{rule[:nonResourceURLs].join(' ')}]" if rule[:nonResourceURLs].any?
    parts << "ResourceNames:[#{rule[:resourceNames].join(' ')}]" if rule[:resourceNames].any?
    parts << "Verbs:[#{rule[:verbs].join(' ')}]" if rule[:verbs].any?

    parts.join(', ')
  end

  def combine_resource_groups(resources, groups)
    return '' if resources.empty?

    parts = resources[0].split('/', 2)
    result = parts[0]

    if groups.count > 0 && groups[0] != ''
      result = result + '.' + groups[0]
    end

    if parts.count == 2
      result = result + '/' + parts[1]
    end

    result
  end
end
