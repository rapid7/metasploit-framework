.SECONDARY:
.SECONDEXPANSION:

lint-charts: ##@Lint Lint Helm Chart
	helm lint meterpreter

generate-deployment:	##@Generate Generate YAML based deployment
	helm template meterpreter meterpreter --set lport="4444" --set lhost="1.1.1.1" > meterpreter.yaml

install-meterpreter: ##@meterpreter Install meterpreter chart
	helm upgrade --create-namespace -i -n metasploit meterpreter ./meterpreter

delete-meterpreter: ##@meterpreter Delete meterpreter chart
	helm -n metasploit delete meterpreter


create-kind-cluster:  ##@Test create kind cluster
	kind create cluster --image kindest/node:v1.18.2 --name metasploit

delete-kind-cluster:  ##@Test delete kind cluster
	kind delete cluster --name metasploit


HELP_FUN = \
         %help; \
         while(<>) { push @{$$help{$$2 // 'options'}}, [$$1, $$3] if /^(.+)\s*:.*\#\#(?:@(\w+))?\s(.*)$$/ }; \
         print "Usage: make [opti@buildons] [target] ...\n\n"; \
     for (sort keys %help) { \
         print "$$_:\n"; \
         for (sort { $$a->[0] cmp $$b->[0] } @{$$help{$$_}}) { \
             $$sep = " " x (30 - length $$_->[0]); \
             print "  $$_->[0]$$sep$$_->[1]\n" ; \
         } print "\n"; }


help: ##@Misc Show this help
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help
