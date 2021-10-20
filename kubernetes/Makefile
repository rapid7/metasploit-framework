#
# 
#
.SECONDARY:
.SECONDEXPANSION:

lint-charts: ##@Lint Lint Helm Chart
	helm lint metasploit
	helm lint kubevenom    

generate-deployment:	##@Generate Generate K8S installation
	helm template metasploit metasploit > metasploit.yaml   

install-metasploit: ##@Metasploit Install Metasploit chart
	find -- metasploit/charts -prune -type d -empty || helm dep update ./metasploit 
	helm upgrade --create-namespace -i -n metasploit metasploit ./metasploit

delete-metasploit: ##@Metasploit Delete Metasploit chart    
	helm -n metasploit delete metasploit

install-kubevenom: ##@Kubevenom Install kubevenom chart
	helm upgrade --create-namespace -i -n metasploit kubevenom ./kubevenom

delete-kubevenom: ##@Kubevenom Delete kubevenom chart    
	helm -n metasploit delete kubevenom    


create-kind-cluster:  ##@Test create KIND cluster
	kind create cluster --image kindest/node:v1.18.2 --name metasploit

delete-kind-cluster:  ##@Test delete KIND cluster
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
