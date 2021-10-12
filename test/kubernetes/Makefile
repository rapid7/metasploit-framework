#.POSIX:
.PHONY: install thinkphp secrets secret-files forward-% help
.DEFAULT_GOAL: help

default: help

install: secret-files thinkphp secrets ## Install all charts

thinkphp:
	helm upgrade --install thinkphp ./thinkphp

secrets: secret-files
	helm upgrade --install secrets ./secrets

forward-thinkphp: ## Forward thinkphp to the host machine on port 9001
	export POD_NAME=$(kubectl get pods --namespace default -l "app.kubernetes.io/name=thinkphp,app.kubernetes.io/instance=thinkphp" -o jsonpath="{.items[0].metadata.name}")
	export CONTAINER_PORT=$(kubectl get pod --namespace default $$POD_NAME -o jsonpath="{.spec.containers[0].ports[0].containerPort}")
	echo "Visit http://127.0.0.1:9001 to use your application"
	kubectl --namespace default port-forward $$POD_NAME --address='0.0.0.0' 9001:$$CONTAINER_PORT

### Creating a sample collection of extractable secret files to ensure Metasploit can correctly extract/parse them all
SECRETS_DIR = ./secrets/files
ALL_SECRETS = $(addprefix $(SECRETS_DIR)/, \
		ssh-auth/ \
		ssh-auth/id-rsa-without-passphrase \
		ssh-auth/id-rsa-with-passphrase \
		ssh-auth/id-ed25519-with-passphrase \
		ssh-auth/id-ed25519-without-passphrase \
		tls/ \
		tls/ca.key \
		tls/ca.crt \
	)
secret-files: $(ALL_SECRETS) ## Generate all secret files
$(SECRETS_DIR)/ssh-auth:
	mkdir $@

$(SECRETS_DIR)/ssh-auth/id-rsa-without-passphrase:
	ssh-keygen -t rsa -f $@ -N 'helloworld'

$(SECRETS_DIR)/ssh-auth/id-rsa-with-passphrase:
	ssh-keygen -t rsa -f $@ -N ''

$(SECRETS_DIR)/ssh-auth/id-ed25519-with-passphrase:
	ssh-keygen -t ed25519 -f $@ -N 'helloworld'

$(SECRETS_DIR)/ssh-auth/id-ed25519-without-passphrase:
	ssh-keygen -t ed25519 -f $@ -N ''

$(SECRETS_DIR)/tls:
	mkdir $@

$(SECRETS_DIR)/tls/ca.key:
	openssl genrsa -out $@ 2048

$(SECRETS_DIR)/tls/ca.crt: $(SECRETS_DIR)/tls/ca.key
	openssl req -x509 -new -nodes -days 365 -key $< -out $@ -subj "/CN=example.com"

HELP_FUN = \
	%help; \
	while(<>) { push @{$$help{$$2 // 'options'}}, [$$1, $$3] if /^(\w+)\s*:.*\#\#(?:@(\w+))?\s(.*)$$/ }; \
	print "usage: make [target]\n\n"; \
	for (keys %help) { \
		print "$$_:\n"; $$sep = " " x (20 - length $$_->[0]); \
		print "  $$_->[0]$$sep$$_->[1]\n" for @{$$help{$$_}}; \
		print "\n"; \
	}

help: ##@miscellaneous Show this help.
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)
