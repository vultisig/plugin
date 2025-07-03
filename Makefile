# adjust to point to your local go-wrappers repo
DYLD_LIBRARY=../go-wrappers/includes/darwin/:$LD_LIBRARY_PATH

up:
	@docker compose up -d --remove-orphans;

up-dev:
	@docker compose -f docker-compose.yaml -f docker-compose.dev.yaml up -d --remove-orphans;

down:
	@docker compose down

down-dev:
	@docker compose -f docker-compose.yaml -f docker-compose.dev.yaml down;

build:
	@docker compose build;

build-dev:
	@docker compose -f docker-compose.yaml -f docker-compose.dev.yaml build;


# Dump database schema
# Usage: make dump-schema CONFIG=config-plugin.yaml
dump-schema:
	@if [ -z "$(CONFIG)" ]; then \
		echo "Error: CONFIG parameter is required. Usage: make dump-schema CONFIG=config-plugin.yaml"; \
		exit 1; \
	fi
	@DSN=$$(yq eval '.database.dsn' $(CONFIG)); \
	pg_dump "$$DSN" --schema-only \
		--no-comments \
		--no-owner \
		--quote-all-identifiers \
		-T public.goose_db_version \
		-T public.goose_db_version_id_seq | sed \
		-e '/^--.*/d' \
		-e '/^SET /d' \
		-e '/^SELECT pg_catalog./d' \
		-e 's/"public"\.//' | awk '/./ { e=0 } /^$$/ { e += 1 } e <= 1' \
		> ./storage/postgres/schema/schema.sql