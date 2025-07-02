--
-- PostgreSQL database dump
--

-- Dumped from database version 17.5 (Debian 17.5-1.pgdg120+1)
-- Dumped by pg_dump version 17.5 (Debian 17.5-1.pgdg120+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plugin_id; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE "public"."plugin_id" AS ENUM (
    'vultisig-dca-0000',
    'vultisig-payroll-0000',
    'vultisig-fees-feee'
);


--
-- Name: trigger_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE "public"."trigger_status" AS ENUM (
    'PENDING',
    'RUNNING'
);


--
-- Name: tx_indexer_status; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE "public"."tx_indexer_status" AS ENUM (
    'PROPOSED',
    'VERIFIED',
    'SIGNED'
);


--
-- Name: tx_indexer_status_onchain; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE "public"."tx_indexer_status_onchain" AS ENUM (
    'PENDING',
    'SUCCESS',
    'FAIL'
);


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION "public"."update_updated_at_column"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = "heap";

--
-- Name: fee; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."fee" (
    "id" "uuid" NOT NULL,
    "fee_run_id" "uuid" NOT NULL,
    "amount" integer NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"()
);


--
-- Name: fee_run; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."fee_run" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "status" character varying(50) DEFAULT 'draft'::character varying NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "tx_id" "uuid",
    "policy_id" "uuid" NOT NULL,
    CONSTRAINT "fee_run_status_check" CHECK ((("status")::"text" = ANY ((ARRAY['draft'::character varying, 'sent'::character varying, 'completed'::character varying, 'failed'::character varying])::"text"[])))
);


--
-- Name: fee_run_with_totals; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW "public"."fee_run_with_totals" AS
 SELECT "fr"."id",
    "fr"."status",
    "fr"."created_at",
    "fr"."updated_at",
    "fr"."tx_id",
    "fr"."policy_id",
    COALESCE("sum"("fi"."amount"), (0)::bigint) AS "total_amount",
    "count"("fi"."id") AS "fee_count"
   FROM ("public"."fee_run" "fr"
     LEFT JOIN "public"."fee" "fi" ON (("fr"."id" = "fi"."fee_run_id")))
  GROUP BY "fr"."id", "fr"."status", "fr"."created_at", "fr"."updated_at", "fr"."tx_id", "fr"."policy_id";


--
-- Name: plugin_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."plugin_policies" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "public_key" "text" NOT NULL,
    "plugin_id" "public"."plugin_id" NOT NULL,
    "plugin_version" "text" NOT NULL,
    "policy_version" integer NOT NULL,
    "signature" "text" NOT NULL,
    "recipe" "text" NOT NULL,
    "active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


--
-- Name: time_triggers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."time_triggers" (
    "id" integer NOT NULL,
    "policy_id" "uuid" NOT NULL,
    "cron_expression" "text" NOT NULL,
    "start_time" timestamp without time zone NOT NULL,
    "end_time" timestamp without time zone,
    "frequency" integer NOT NULL,
    "interval" integer NOT NULL,
    "last_execution" timestamp without time zone,
    "status" "public"."trigger_status" NOT NULL,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: time_triggers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE "public"."time_triggers_id_seq"
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: time_triggers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE "public"."time_triggers_id_seq" OWNED BY "public"."time_triggers"."id";


--
-- Name: tx_indexer; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE "public"."tx_indexer" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "plugin_id" character varying(255) NOT NULL,
    "tx_hash" character varying(255),
    "chain_id" integer NOT NULL,
    "policy_id" "uuid" NOT NULL,
    "token_id" character varying(255) NOT NULL,
    "from_public_key" character varying(255) NOT NULL,
    "to_public_key" character varying(255) NOT NULL,
    "proposed_tx_hex" "text" NOT NULL,
    "status" "public"."tx_indexer_status" DEFAULT 'PROPOSED'::"public"."tx_indexer_status" NOT NULL,
    "status_onchain" "public"."tx_indexer_status_onchain",
    "lost" boolean DEFAULT false NOT NULL,
    "broadcasted_at" timestamp without time zone,
    "created_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    "updated_at" timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: time_triggers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."time_triggers" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."time_triggers_id_seq"'::"regclass");


--
-- Data for Name: fee; Type: TABLE DATA; Schema: public; Owner: -
--

COPY "public"."fee" ("id", "fee_run_id", "amount", "created_at") FROM stdin;
\.


--
-- Data for Name: fee_run; Type: TABLE DATA; Schema: public; Owner: -
--

COPY "public"."fee_run" ("id", "status", "created_at", "updated_at", "tx_id", "policy_id") FROM stdin;
\.


--
-- Data for Name: plugin_policies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY "public"."plugin_policies" ("id", "public_key", "plugin_id", "plugin_version", "policy_version", "signature", "recipe", "active", "created_at", "updated_at") FROM stdin;
\.


--
-- Data for Name: time_triggers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY "public"."time_triggers" ("id", "policy_id", "cron_expression", "start_time", "end_time", "frequency", "interval", "last_execution", "status", "created_at") FROM stdin;
\.


--
-- Data for Name: tx_indexer; Type: TABLE DATA; Schema: public; Owner: -
--

COPY "public"."tx_indexer" ("id", "plugin_id", "tx_hash", "chain_id", "policy_id", "token_id", "from_public_key", "to_public_key", "proposed_tx_hex", "status", "status_onchain", "lost", "broadcasted_at", "created_at", "updated_at") FROM stdin;
\.


--
-- Name: time_triggers_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('"public"."time_triggers_id_seq"', 1, false);


--
-- Name: fee fee_id_fee_run_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."fee"
    ADD CONSTRAINT "fee_id_fee_run_id_key" UNIQUE ("id", "fee_run_id");


--
-- Name: fee fee_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."fee"
    ADD CONSTRAINT "fee_pkey" PRIMARY KEY ("id");


--
-- Name: fee_run fee_run_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."fee_run"
    ADD CONSTRAINT "fee_run_pkey" PRIMARY KEY ("id");


--
-- Name: plugin_policies plugin_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."plugin_policies"
    ADD CONSTRAINT "plugin_policies_pkey" PRIMARY KEY ("id");


--
-- Name: time_triggers time_triggers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."time_triggers"
    ADD CONSTRAINT "time_triggers_pkey" PRIMARY KEY ("id");


--
-- Name: tx_indexer tx_indexer_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."tx_indexer"
    ADD CONSTRAINT "tx_indexer_pkey" PRIMARY KEY ("id");


--
-- Name: idx_fee_id_fee_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_fee_id_fee_run_id" ON "public"."fee" USING "btree" ("fee_run_id");


--
-- Name: idx_fee_run_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_fee_run_created_at" ON "public"."fee_run" USING "btree" ("created_at");


--
-- Name: idx_fee_run_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_fee_run_status" ON "public"."fee_run" USING "btree" ("status");


--
-- Name: idx_plugin_policies_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_plugin_policies_active" ON "public"."plugin_policies" USING "btree" ("active");


--
-- Name: idx_plugin_policies_plugin_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_plugin_policies_plugin_id" ON "public"."plugin_policies" USING "btree" ("plugin_id");


--
-- Name: idx_plugin_policies_public_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_plugin_policies_public_key" ON "public"."plugin_policies" USING "btree" ("public_key");


--
-- Name: idx_time_triggers_policy_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_time_triggers_policy_id" ON "public"."time_triggers" USING "btree" ("policy_id");


--
-- Name: idx_time_triggers_start_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_time_triggers_start_time" ON "public"."time_triggers" USING "btree" ("start_time");


--
-- Name: idx_tx_indexer_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_tx_indexer_key" ON "public"."tx_indexer" USING "btree" ("chain_id", "plugin_id", "policy_id", "token_id", "to_public_key", "created_at");


--
-- Name: idx_tx_indexer_status_onchain_lost; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX "idx_tx_indexer_status_onchain_lost" ON "public"."tx_indexer" USING "btree" ("status_onchain", "lost");


--
-- Name: fee_run update_fee_run_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER "update_fee_run_updated_at" BEFORE UPDATE ON "public"."fee_run" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();


--
-- Name: fee fee_fee_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."fee"
    ADD CONSTRAINT "fee_fee_run_id_fkey" FOREIGN KEY ("fee_run_id") REFERENCES "public"."fee_run"("id") ON DELETE CASCADE;


--
-- Name: fee_run fee_run_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."fee_run"
    ADD CONSTRAINT "fee_run_policy_id_fkey" FOREIGN KEY ("policy_id") REFERENCES "public"."plugin_policies"("id") ON DELETE CASCADE;


--
-- Name: fee_run fee_run_tx_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."fee_run"
    ADD CONSTRAINT "fee_run_tx_id_fkey" FOREIGN KEY ("tx_id") REFERENCES "public"."tx_indexer"("id") ON DELETE SET NULL;


--
-- Name: time_triggers time_triggers_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY "public"."time_triggers"
    ADD CONSTRAINT "time_triggers_policy_id_fkey" FOREIGN KEY ("policy_id") REFERENCES "public"."plugin_policies"("id");


--
-- PostgreSQL database dump complete
--

