.PHONY: install thinkphp forward-thinkphp lucee forward-lucee dashboard forward-dashboard admin-token service-token secrets secret-files patch-docker-desktop-admin-service-accounts help
.DEFAULT_GOAL: help

RED := $(shell tput -Txterm setaf 1)
RESET := $(shell tput -Txterm sgr0)

# Detect if docker-desktop is defaulting service accounts to have full admin cluster privileges by default
# https://github.com/docker/for-mac/issues/4774#issuecomment-6622851890
HAS_CLUSTER_ADMIN_SERVICE_ACCOUNT=$(shell kubectl get clusterrolebinding docker-for-desktop-binding -o yaml 2>/dev/null | grep -c 'name: system:serviceaccounts$$')

default: help
all: run  ##@install Install all charts
install: secret-files thinkphp lucee secrets dashboard ##@install Install all charts

thinkphp: ##@install Install vulnerable thinkphp application with full cluster access
	helm upgrade --install thinkphp ./thinkphp

lucee: ##@install Install vulnerable lucee application with minimal cluster access
	helm upgrade --install lucee ./lucee
ifeq ($(HAS_CLUSTER_ADMIN_SERVICE_ACCOUNT),1)
	@echo "${RED}[!] docker-desktop detected. Additionally run 'make patch-docker-desktop-admin-service-accounts' to ensure lucee does not have full cluster access by default${RESET}" 2>&2
endif

dashboard: ##@install Install the Kubernetes dashboard
	helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/
	helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard

secrets: secret-files ##@install Install enumerable secrets
	helm upgrade --install secrets ./secrets

forward-thinkphp: ##@forward Forward thinkphp to the host machine on port 9001
	$(call forward,thinkphp,9001)

forward-lucee: ##@forward Forward lucee to the host machine on port 9002
	$(call forward,lucee,9002)

forward-dashboard: ##@forward Forward Kubernetes dashboard to the host machine on port 8443
	$(call forward,kubernetes-dashboard,8443)

admin-token: ##@tokens Create an admin token which will have full access to the cluster, also useful for the Kubernetes Dashboard
	kubectl create -n default serviceaccount admin-sa --dry-run=client -o yaml | kubectl apply -f -
	kubectl create -n default clusterrolebinding admin-sa-binding --clusterrole=cluster-admin --serviceaccount=default:admin-sa --dry-run=client -o yaml | kubectl apply -f -
	echo $$(kubectl get secret -n default $$(kubectl -n default get serviceaccount admin-sa -o jsonpath="{.secrets[0].name}") -o jsonpath="{.data.token}" | base64 -d)

service-token: ##@tokens Create a Kubernetes service token for the default service account
	echo $$(kubectl get secret -n default $$(kubectl -n default get serviceaccount default -o jsonpath="{.secrets[0].name}") -o jsonpath="{.data.token}" | base64 -d)

patch-docker-desktop-admin-service-accounts: ##@miscellaneous Patch service accounts to not have full cluster access by default on docker-desktop - https://github.com/docker/for-mac/issues/4774
	# https://github.com/docker/for-mac/issues/4774#issuecomment-6622851890
	kubectl patch clusterrolebinding docker-for-desktop-binding --type=json --patch $$'[{"op":"replace", "path":"/subjects/0/name", "value":"system:serviceaccounts:kube-system"}]'

# forward a running pod on the given port
# ${1}=podname
# ${2}=port
define forward
	export POD_NAME=$$(kubectl get pods --namespace default -l "app.kubernetes.io/name=${1},app.kubernetes.io/instance=${1}" -o jsonpath="{.items[0].metadata.name}"); \
	export CONTAINER_PORT=$$(kubectl get pod --namespace default $$POD_NAME -o jsonpath="{.spec.containers[0].ports[0].containerPort}"); \
	echo; \
	echo "Visit http://127.0.0.1:${2} to use your application"; \
	kubectl --namespace default port-forward $$POD_NAME --address='0.0.0.0' ${2}:$$CONTAINER_PORT
endef

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
secret-files: $(ALL_SECRETS) ##@create Create all secret files
$(SECRETS_DIR)/ssh-auth/:
	mkdir $@

$(SECRETS_DIR)/ssh-auth/id-rsa-without-passphrase:
	ssh-keygen -t rsa -f $@ -N 'helloworld'

$(SECRETS_DIR)/ssh-auth/id-rsa-with-passphrase:
	ssh-keygen -t rsa -f $@ -N ''

$(SECRETS_DIR)/ssh-auth/id-ed25519-with-passphrase:
	ssh-keygen -t ed25519 -f $@ -N 'helloworld'

$(SECRETS_DIR)/ssh-auth/id-ed25519-without-passphrase:
	ssh-keygen -t ed25519 -f $@ -N ''

$(SECRETS_DIR)/tls/:
	mkdir $@

$(SECRETS_DIR)/tls/ca.key:
	openssl genrsa -out $@ 2048

$(SECRETS_DIR)/tls/ca.crt: $(SECRETS_DIR)/tls/ca.key
	openssl req -x509 -new -nodes -days 365 -key $< -out $@ -subj "/CN=example.com"

HELP_FUN = \
	%help, @order; \
	while(<>) { \
		if(/^([a-z0-9_-]+):.*\#\#(?:@(\w+))?\s(.*)$$/) { \
			push(@{$$help{$$2}}, [$$1, $$3]); \
			push @order, $$2 unless $$count{$$2}++; \
		} \
	}; \
	print "usage: make [target]\n\n"; \
	for ( @order ) { \
		print "$$_:\n"; \
		printf("  %-20s %s\n", $$_->[0], $$_->[1]) for @{$$help{$$_}}; \
		print "\n"; \
	}
help: ##@miscellaneous Show this help.
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)
