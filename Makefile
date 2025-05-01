# adjust to point to your local go-wrappers repo
DYLD_LIBRARY=../go-wrappers/includes/darwin/:$LD_LIBRARY_PATH

up:
	@docker compose up -d --remove-orphans;

down:
	@docker compose down

verifier-server:
	@DYLD_LIBRARY_PATH=$(DYLD_LIBRARY) VS_CONFIG_NAME=config-verifier go run cmd/vultisigner/main.go

verifier-worker:
	@DYLD_LIBRARY_PATH=$(DYLD_LIBRARY) VS_CONFIG_NAME=config-verifier go run cmd/worker/main.go
	
plugin-server:
	@DYLD_LIBRARY_PATH=$(DYLD_LIBRARY) VS_CONFIG_NAME=config-plugin go run cmd/vultisigner/main.go

plugin-worker:
	@DYLD_LIBRARY_PATH=$(DYLD_LIBRARY) VS_CONFIG_NAME=config-plugin go run cmd/worker/main.go