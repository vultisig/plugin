
CREATE TYPE "plugin_id" AS ENUM (
    'vultisig-dca-0000',
    'vultisig-payroll-0000',
    'vultisig-fees-feee'
);

CREATE TYPE "trigger_status" AS ENUM (
    'PENDING',
    'RUNNING'
);

CREATE TYPE "tx_indexer_status" AS ENUM (
    'PROPOSED',
    'VERIFIED',
    'SIGNED'
);

CREATE TYPE "tx_indexer_status_onchain" AS ENUM (
    'PENDING',
    'SUCCESS',
    'FAIL'
);

CREATE TABLE "plugin_policies" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "public_key" "text" NOT NULL,
    "plugin_id" "plugin_id" NOT NULL,
    "plugin_version" "text" NOT NULL,
    "policy_version" integer NOT NULL,
    "signature" "text" NOT NULL,
    "recipe" "text" NOT NULL,
    "active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);

CREATE TABLE "time_triggers" (
    "id" integer NOT NULL,
    "policy_id" "uuid" NOT NULL,
    "cron_expression" "text" NOT NULL,
    "start_time" timestamp without time zone NOT NULL,
    "end_time" timestamp without time zone,
    "frequency" integer NOT NULL,
    "interval" integer NOT NULL,
    "last_execution" timestamp without time zone,
    "status" "trigger_status" NOT NULL,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);

CREATE SEQUENCE "time_triggers_id_seq"
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE "time_triggers_id_seq" OWNED BY "public"."time_triggers"."id";

CREATE TABLE "tx_indexer" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "plugin_id" character varying(255) NOT NULL,
    "tx_hash" character varying(255),
    "chain_id" integer NOT NULL,
    "policy_id" "uuid" NOT NULL,
    "token_id" character varying(255) NOT NULL,
    "from_public_key" character varying(255) NOT NULL,
    "to_public_key" character varying(255) NOT NULL,
    "proposed_tx_hex" "text" NOT NULL,
    "status" "tx_indexer_status" DEFAULT 'PROPOSED'::"public"."tx_indexer_status" NOT NULL,
    "status_onchain" "tx_indexer_status_onchain",
    "lost" boolean DEFAULT false NOT NULL,
    "broadcasted_at" timestamp without time zone,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updated_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

ALTER TABLE ONLY "time_triggers" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."time_triggers_id_seq"'::"regclass");

ALTER TABLE ONLY "plugin_policies"
    ADD CONSTRAINT "plugin_policies_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "time_triggers"
    ADD CONSTRAINT "time_triggers_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "tx_indexer"
    ADD CONSTRAINT "tx_indexer_pkey" PRIMARY KEY ("id");

CREATE INDEX "idx_plugin_policies_active" ON "plugin_policies" USING "btree" ("active");

CREATE INDEX "idx_plugin_policies_plugin_id" ON "plugin_policies" USING "btree" ("plugin_id");

CREATE INDEX "idx_plugin_policies_public_key" ON "plugin_policies" USING "btree" ("public_key");

CREATE INDEX "idx_time_triggers_policy_id" ON "time_triggers" USING "btree" ("policy_id");

CREATE INDEX "idx_time_triggers_start_time" ON "time_triggers" USING "btree" ("start_time");

CREATE INDEX "idx_tx_indexer_key" ON "tx_indexer" USING "btree" ("chain_id", "plugin_id", "policy_id", "token_id", "to_public_key", "created_at");

CREATE INDEX "idx_tx_indexer_status_onchain_lost" ON "tx_indexer" USING "btree" ("status_onchain", "lost");

ALTER TABLE ONLY "time_triggers"
    ADD CONSTRAINT "time_triggers_policy_id_fkey" FOREIGN KEY ("policy_id") REFERENCES "plugin_policies"("id");

