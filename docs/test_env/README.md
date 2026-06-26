# test_env Design Documentation

This directory contains the architecture and workflow design for the `test_env` (VulnEnv) plugin.

## Architecture Documents

| Document | Description |
|----------|-------------|
| [01-command-dispatcher.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/architecture/01-command-dispatcher.md) | How `test_env` is added to msfconsole via plugin dispatcher |
| [02-module-metadata.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/architecture/02-module-metadata.md) | How modules expose `VulnEnv` metadata and how the plugin reads it |
| [03-database-schema.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/architecture/03-database-schema.md) | Registry persistence: in-memory Phase 1, PostgreSQL Phase 2 |
| [04-environment-schema.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/architecture/04-environment-schema.md) | YAML schema for shared environment definitions in `data/vuln_envs/` |
| [05-runtime-adapter.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/architecture/05-runtime-adapter.md) | Docker/Podman abstraction, port allocation, container labels |

## Workflow & Planning Documents

| Document | Description |
|----------|-------------|
| [reference_modules.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/reference_modules.md) | 3 reference modules selected for implementation (ActiveMQ, Jenkins, Drupal) |
| [workflow.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/workflow.md) | Target user workflows and console transcripts (acceptance criteria) |
| [ci_workflow.md](https://github.com/Nayeraneru/metasploit-framework/blob/vulnenv-week1/docs/ci_workflow.md) | GitHub Actions CI integration with resource scripts |

## Plugin File

- `plugins/test_env.rb` — Main plugin implementation (Week 1 skeleton)

```
nayera@Nero:~/git/metasploit-framework$ ./msfconsole -q -x "load test_env; exit"
[*] VulnEnv plugin loaded.
[*] Successfully loaded plugin: vulnenv

nayera@Nero:~/git/metasploit-framework$ ./msfconsole -q -x "load test_env; test_env help; exit"
[*] VulnEnv plugin loaded.
[*] Successfully loaded plugin: vulnenv
Usage: test_env <command>

Commands:
  build      Build and launch environment for active module
  list       List tracked environments
  stop <ID>  Stop a running environment
  start <ID> Restart a stopped environment
  remove <ID> Tear down an environment
  remove-all Tear down all environments
  exec <ID>  Execute exploit against environment
  help       Show this help
```

## Data Files

- `data/vuln_envs/jenkins.yml` — Reference environment definition (Week 1 draft)
