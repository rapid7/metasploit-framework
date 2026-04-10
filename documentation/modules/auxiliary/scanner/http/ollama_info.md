## Vulnerable Application

This module identifies ollama instances and enumerates the LLM
models which have been loaded and are running.

### Building Image

Write the following dockerfile.

```dockerfile
FROM ollama/ollama

EXPOSE 11434

VOLUME /root/.ollama

RUN /bin/ollama serve & \
    sleep 5 && \
    /bin/ollama pull llama3.2:1b && \
    /bin/ollama pull qwen3.5:0.8b && \
    /bin/ollama pull smollm:135m && \
    printf 'FROM smollm:135m\nSYSTEM "you are an AI assistant and this is your system prompt"\n' > /Modelfile && \
    /bin/ollama create my-model -f /Modelfile

RUN printf '#!/bin/bash\n/bin/ollama serve &\nsleep 3\ncurl -s http://localhost:11434/api/chat -d '"'"'{"model":"my-model","stream":false,"messages":[{"role":"user","content":"warmup"}]}'"'"'\nwait\n' > /start.sh && \
    chmod +x /start.sh

ENTRYPOINT []
CMD ["/start.sh"]
```

Build and start it.

```
docker build -t my-ollama .
docker run -d -p 11434:11434 --name my-ollama my-ollama
```

## Verification Steps

1. Start the ollama docker
2. Start msfconsole
3. Do: `use auxiliary/scanner/http/ollama_info`
4. Do: `set rhosts [IPs]`
5. Do: `run`
6. You should get information about the models in teh ollama instance

## Options

## Scenarios

### Docker image

```
msf > use auxiliary/scanner/http/ollama_info
msf auxiliary(scanner/http/ollama_info) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf auxiliary(scanner/http/ollama_info) > run
[*] Checking 127.0.0.1
[*]   Found model: my-model:latest
[*]   Found model: smollm:135m
[*]   Found model: qwen3.5:0.8b
[*]   Found model: llama3.2:1b
[*] 127.0.0.1 Ollama Models
=======================

  Name      Release  Status     Size       Parameter Size  Temperature  System Prompt
  ----      -------  ------     ----       --------------  -----------  -------------
  llama3.2  1b       Installed  1.23 GB    1.2B            N/A          N/A
  my-model  latest   Running    130.77 MB  134.52M         0.2          you are an AI assistant and this is your system prompt
  qwen3.5   0.8b     Installed  988.05 MB  873.44M         1            N/A
  smollm    135m     Installed  87.49 MB   134.52M         0.2          N/A

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
