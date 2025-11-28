-- Supabase Database Schema
-- Run this SQL in your Supabase SQL Editor to create the tables

-- Assets table for network scan results
CREATE TABLE IF NOT EXISTS public.assets (
    id BIGSERIAL NOT NULL,
    host_ip TEXT NOT NULL,
    host_name TEXT NULL,
    mac_address TEXT NULL,
    vendor TEXT NULL,
    is_online BOOLEAN NOT NULL DEFAULT FALSE,
    ping_time INTEGER NULL DEFAULT 0,
    scan_time TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    synced BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    project_name TEXT NULL,
    CONSTRAINT assets_pkey PRIMARY KEY (id)
) TABLESPACE pg_default;

CREATE INDEX IF NOT EXISTS idx_assets_synced ON public.assets USING btree (synced) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_assets_host_ip ON public.assets USING btree (host_ip) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_assets_project_name ON public.assets USING btree (project_name) TABLESPACE pg_default;

-- Attack logs table
CREATE TABLE IF NOT EXISTS public.attack_logs (
    id BIGSERIAL NOT NULL,
    project_name TEXT NULL,
    attack_type TEXT NOT NULL,
    protocol TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    source_mac TEXT NULL,
    target_ip TEXT NOT NULL,
    target_mac TEXT NULL,
    target_port INTEGER NULL DEFAULT 0,
    target_rate_mbps REAL NOT NULL,
    packets_sent BIGINT NULL DEFAULT 0,
    duration_seconds INTEGER NULL DEFAULT 0,
    start_time TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    stop_time TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    synced BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT attack_logs_pkey PRIMARY KEY (id)
) TABLESPACE pg_default;

CREATE INDEX IF NOT EXISTS idx_attack_logs_synced ON public.attack_logs USING btree (synced) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_attack_logs_project_name ON public.attack_logs USING btree (project_name) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_attack_logs_start_time ON public.attack_logs USING btree (start_time) TABLESPACE pg_default;

-- Enable Row Level Security (RLS)
ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attack_logs ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist, then create new ones
DROP POLICY IF EXISTS "Allow anonymous inserts to assets" ON public.assets;
DROP POLICY IF EXISTS "Allow anonymous selects from assets" ON public.assets;
DROP POLICY IF EXISTS "Allow anonymous inserts to attack_logs" ON public.attack_logs;
DROP POLICY IF EXISTS "Allow anonymous selects from attack_logs" ON public.attack_logs;

-- Policies for assets table: Allow anonymous inserts and selects
CREATE POLICY "Allow anonymous inserts to assets" ON public.assets
    FOR INSERT
    TO anon
    WITH CHECK (true);

CREATE POLICY "Allow anonymous selects from assets" ON public.assets
    FOR SELECT
    TO anon
    USING (true);

-- Policies for attack_logs table: Allow anonymous inserts and selects
CREATE POLICY "Allow anonymous inserts to attack_logs" ON public.attack_logs
    FOR INSERT
    TO anon
    WITH CHECK (true);

CREATE POLICY "Allow anonymous selects from attack_logs" ON public.attack_logs
    FOR SELECT
    TO anon
    USING (true);
