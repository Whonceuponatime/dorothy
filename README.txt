# Dorothy - Maritime Network Testing Tool

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
- Windows OS
- .NET 7.0 or higher
- Administrative privileges
- Network adapter with packet injection support
- WinPcap/Npcap installed

### Technical Architecture
- Built on .NET 7.0
- Uses SharpPcap for packet manipulation
- WPF-based user interface
- Multi-threaded attack simulation
- Event-driven logging system

## Usage Guidelines
This tool should only be used by authorized personnel in maritime environments for:
- Network resilience testing
- Security evaluation
- Performance assessment
- Infrastructure validation

## Author
Hojin Samuel Tae  
Maritime Cybersecurity Researcher  
SeaNet

## License
Proprietary software. All rights reserved.  
Copyright © 2024 SeaNet