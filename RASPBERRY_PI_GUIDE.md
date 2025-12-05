# Running on Raspberry Pi Guide

## Overview
This application is a Windows WPF application that cannot run directly on Raspberry Pi (which typically runs Linux). However, there are several approaches depending on what you want to accomplish.

## Option 1: Running SQL Migrations (Recommended for Database Setup)

If you just need to run the SQL migration file (`create_link_attack_log_user_function.sql`), you can do this from Raspberry Pi:

### Prerequisites
- Raspberry Pi with internet connection
- Access to your Supabase project

### Method 1: Using Supabase Dashboard (Easiest)
1. Open your Supabase project dashboard in a web browser on Raspberry Pi
2. Navigate to **SQL Editor**
3. Copy and paste the contents of `migrations/create_link_attack_log_user_function.sql`
4. Click **Run** to execute the migration

### Method 2: Using psql Command Line
```bash
# Install PostgreSQL client on Raspberry Pi
sudo apt update
sudo apt install postgresql-client

# Connect to Supabase (replace with your connection string)
psql "postgresql://postgres:[YOUR-PASSWORD]@db.[YOUR-PROJECT-REF].supabase.co:5432/postgres" -f migrations/create_link_attack_log_user_function.sql
```

### Method 3: Using Supabase CLI
```bash
# Install Supabase CLI
npm install -g supabase

# Login to Supabase
supabase login

# Link to your project
supabase link --project-ref [YOUR-PROJECT-REF]

# Run the migration
supabase db push migrations/create_link_attack_log_user_function.sql
```

## Option 2: Running the Full Application

Since this is a WPF application (Windows-only), you have these options:

### Option 2A: Use Windows on Raspberry Pi (Not Recommended)
- Install Windows IoT Core or Windows 10/11 ARM (if supported)
- This is complex and has limited hardware support
- Not recommended for most use cases

### Option 2B: Create a Linux-Compatible Version

To run on Raspberry Pi, you would need to:

1. **Create a Console/CLI Version**
   - Remove WPF dependencies
   - Create a cross-platform console application
   - Target `net8.0` instead of `net8.0-windows`

2. **Create a Web API Version**
   - Convert to ASP.NET Core Web API
   - Create a web interface accessible from any device
   - Can run on Raspberry Pi and access from any browser

3. **Use Remote Desktop/VNC**
   - Run the Windows application on a Windows machine
   - Access it remotely from Raspberry Pi using RDP or VNC

### Option 2C: Docker Container (If Applicable)
If you containerize parts of the application:
```bash
# On Raspberry Pi
docker pull mcr.microsoft.com/dotnet/aspnet:8.0
# Run your containerized application
```

## Option 3: Running Network Components Only

If you only need the network testing functionality (without the GUI):

### Create a Minimal Console App
1. Extract the core network attack classes (`Models/*.cs`)
2. Create a new console project targeting `net8.0` (not `net8.0-windows`)
3. Remove WPF-specific code
4. Note: `SharpPcap` may need Linux-specific dependencies

### Install Required Dependencies on Raspberry Pi
```bash
# For SharpPcap on Linux, you may need:
sudo apt-get install libpcap-dev

# Install .NET 8 SDK on Raspberry Pi
# Follow instructions at: https://dotnet.microsoft.com/download/dotnet/8.0
```

## Recommended Approach

**For SQL Migrations:**
- Use Option 1 (Supabase Dashboard or CLI) - this is the simplest

**For Full Application:**
- Option 2B (Create Linux-Compatible Version) is the most practical
- Consider creating a web-based interface using ASP.NET Core
- Or use a cross-platform UI framework like Avalonia UI

## Quick Start: Running SQL Migration

The simplest way to run your SQL migration on Raspberry Pi:

```bash
# On Raspberry Pi, open terminal
cd /path/to/your/project

# If you have Supabase CLI installed:
supabase db push migrations/create_link_attack_log_user_function.sql

# Or manually copy the SQL and run in Supabase Dashboard
cat migrations/create_link_attack_log_user_function.sql
# Then paste into Supabase SQL Editor
```

## Notes

- The current application uses `SharpPcap` which requires platform-specific native libraries
- WPF is Windows-only and cannot run on Linux/Raspberry Pi
- The database operations (Supabase) are cross-platform and can work from any device
- Consider creating a separate Linux-compatible version if you need the full functionality on Raspberry Pi

## Next Steps

If you want to create a Linux-compatible version, I can help you:
1. Create a console application version
2. Create a web API version
3. Modify the project to support cross-platform builds

Let me know which approach you'd like to pursue!

