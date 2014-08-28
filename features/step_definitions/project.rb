project_database_yaml_path = Rails.root.join('config', 'database.yml').to_path
backup_project_database_yaml_path = "#{project_database_yaml_path}.cucumber.bak"

Before do
  if File.exist?(backup_project_database_yaml_path)
    File.delete(backup_project_database_yaml_path)
  end
end

Given /^the project "database.yml" exists with:$/ do |file_content|
  if File.exist?(project_database_yaml_path)
    File.rename(project_database_yaml_path, backup_project_database_yaml_path)
  end

  write_file(project_database_yaml_path, file_content)
end

After do
  if File.exist?(backup_project_database_yaml_path)
    File.rename(backup_project_database_yaml_path, project_database_yaml_path)
  end
end