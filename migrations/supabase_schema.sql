-- Supabase Database Schema (Simplified)
-- NOTE: For the COMPLETE schema with AUDIT LOGGING, use: supabase_schema_with_audit.sql
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
    hardware_id TEXT NULL,
    machine_name TEXT NULL,
    username TEXT NULL,
    user_id UUID NULL,
    ports TEXT NULL,
    CONSTRAINT assets_pkey PRIMARY KEY (id)
) TABLESPACE pg_default;

CREATE INDEX IF NOT EXISTS idx_assets_synced ON public.assets USING btree (synced) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_assets_host_ip ON public.assets USING btree (host_ip) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_assets_project_name ON public.assets USING btree (project_name) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_assets_hardware_id ON public.assets USING btree (hardware_id) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_assets_user_id ON public.assets USING btree (user_id) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_assets_username ON public.assets USING btree (username) TABLESPACE pg_default;

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
    hardware_id TEXT NULL,
    machine_name TEXT NULL,
    username TEXT NULL,
    user_id UUID NULL,
    CONSTRAINT attack_logs_pkey PRIMARY KEY (id)
) TABLESPACE pg_default;

CREATE INDEX IF NOT EXISTS idx_attack_logs_synced ON public.attack_logs USING btree (synced) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_attack_logs_project_name ON public.attack_logs USING btree (project_name) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_attack_logs_start_time ON public.attack_logs USING btree (start_time) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_attack_logs_hardware_id ON public.attack_logs USING btree (hardware_id) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_attack_logs_user_id ON public.attack_logs USING btree (user_id) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_attack_logs_username ON public.attack_logs USING btree (username) TABLESPACE pg_default;

-- Ports table for network scan port results
-- Note: If the table already exists without host_ip, run migrations/add_host_ip_to_ports.sql first
CREATE TABLE IF NOT EXISTS public.ports (
    id BIGSERIAL NOT NULL,
    asset_id BIGINT NULL,
    host_ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'TCP',
    service TEXT NULL,
    banner TEXT NULL,
    scan_time TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    synced BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    project_name TEXT NULL,
    hardware_id TEXT NULL,
    machine_name TEXT NULL,
    username TEXT NULL,
    user_id UUID NULL,
    CONSTRAINT ports_pkey PRIMARY KEY (id),
    CONSTRAINT fk_ports_asset FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE
) TABLESPACE pg_default;

-- Migration: Add host_ip column if table exists without it
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = 'ports'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = 'ports' 
        AND column_name = 'host_ip'
    ) THEN
        ALTER TABLE public.ports ADD COLUMN host_ip TEXT NOT NULL DEFAULT '';
        
        -- Update existing rows to set host_ip from asset_id if possible
        UPDATE public.ports p
        SET host_ip = a.host_ip
        FROM public.assets a
        WHERE p.asset_id = a.id
        AND p.host_ip = '';
        
        -- Remove default after updating existing rows
        ALTER TABLE public.ports ALTER COLUMN host_ip DROP DEFAULT;
        
        RAISE NOTICE 'Added host_ip column to existing ports table';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ports_asset_id ON public.ports USING btree (asset_id) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_ports_host_ip ON public.ports USING btree (host_ip) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_ports_synced ON public.ports USING btree (synced) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_ports_project_name ON public.ports USING btree (project_name) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_ports_hardware_id ON public.ports USING btree (hardware_id) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_ports_user_id ON public.ports USING btree (user_id) TABLESPACE pg_default;
CREATE INDEX IF NOT EXISTS idx_ports_username ON public.ports USING btree (username) TABLESPACE pg_default;

-- Enable Row Level Security (RLS)
ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attack_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ports ENABLE ROW LEVEL SECURITY;

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

-- Policies for ports table: Allow anonymous inserts and selects
CREATE POLICY "Allow anonymous inserts to ports" ON public.ports
    FOR INSERT
    TO anon
    WITH CHECK (true);

CREATE POLICY "Allow anonymous selects from ports" ON public.ports
    FOR SELECT
    TO anon
    USING (true);
