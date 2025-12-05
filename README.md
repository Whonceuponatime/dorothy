# Maritime Network Testing Tool 🚢

## Overview
Dorothy is a specialized network testing tool designed for maritime cybersecurity evaluation. Developed by Hojin Samuel Tae, this tool simulates various network stress conditions to test the resilience of maritime network infrastructure.

## Disclaimer
**AUTHORIZED USE ONLY**

This software is intended strictly for legitimate network testing in controlled maritime environments. Users must:
- Have explicit authorization before conducting any tests
- Only use in controlled testing environments
- Obtain necessary permissions from network owners/operators
- Accept full responsibility for usage

SeaNet and its affiliates assume no responsibility for any misuse, unauthorized access, or damages resulting from the use of this program.

## Technical Specifications

### Attack Types
- TCP SYN Flood
- UDP Flood
- ICMP Flood
- ARP Spoofing
- Broadcast Attack Simulation
- Multicast Attack Simulation

### Network Performance
- Configurable packet rates (Mbps)
- Real-time rate limiting
- Supports IPv4 addressing
- MAC address spoofing capabilities

### Packet Rate Calculation
The program calculates packet transmission rates using the following formula:
```
Bytes per second = Megabits per second * 125,000
```

### Rate Limiting Implementation
Rate limiting is implemented through precise timing controls:
- Packet size monitoring
- Transmission timing adjustment
- Bandwidth regulation
- Buffer management

Reference implementation:

### Features
- Real-time attack monitoring
- Network interface selection
- Customizable attack parameters
- Logging system with detailed metrics
- Advanced authentication system
- Status monitoring and reporting

### System Requirements
- Linux OS (Raspberry Pi OS recommended)
- .NET 8.0 SDK
- Root/sudo privileges for packet injection
- Network adapter with packet injection support
- X11 display server (for GUI)

### Technical Architecture
- Built on .NET 8.0
- Uses SharpPcap for packet manipulation
- Avalonia-based cross-platform UI
- Multi-threaded attack simulation
- Event-driven logging system

## Quick Start

### One-Command Setup (Recommended)

**Just run this one script - it does everything:**

```bash
chmod +x setup.sh
./setup.sh
```

That's it! This single script will:
- Clean previous builds
- Restore NuGet packages
- Build the project
- Publish for Raspberry Pi (ARM64)
- Set up the `dorothy` command
- Source your bashrc

**Then run the application:**
```bash
dorothy
```

---

### Other Scripts (Optional - Only if you need them)

If you need more control, you can use these individual scripts:

- **`build.sh`** - Just builds the project (for development)
- **`run.sh`** - Just runs the built application
- **`publish.sh [linux-arm64|linux-x64]`** - Just publishes (without setup)
- **`setup-dorothy-command.sh [runtime]`** - Just sets up the command (after publishing)

**But you don't need these - just use `setup.sh`!**

For more details, see [BUILD_AND_RUN_GUIDE.md](BUILD_AND_RUN_GUIDE.md).

## Usage Guidelines
This tool should only be used by authorized personnel in maritime environments for:
- Network resilience testing
- Security evaluation
- Performance assessment
- Infrastructure validation

## Author
Hojin Samuel Tae  
Cybersecurity Engineer  
SeaNet

## License
Proprietary software. All rights reserved.  
Copyright © 2024 SeaNet

## Packet Engineering & Network Analysis 📡

### Packet Creation & Structure 📦
The tool constructs network packets with precise control over:

- Ethernet Frame Construction 🔧
