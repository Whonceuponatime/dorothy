# SEACURE(TOOL) Release Notes

## Version 2.3.1 — 2026-03-17

### Bug Fixes

- **UDP Flood — Malformed Packets Fixed**
  - Replaced the Windows raw socket approach (`SocketType.Raw / ProtocolType.Udp`) with SharpPcap Layer-2 injection using PacketDotNet.
  - Root cause: `BitConverter.GetBytes()` writes little-endian bytes; UDP/IP headers require big-endian (network byte order). Source port 80 was being sent as `[0x50, 0x00]` instead of `[0x00, 0x50]`, making every UDP packet appear malformed in Wireshark and at the destination.
  - Additionally, Windows Vista+ silently blocks raw UDP packet injection at the kernel level, meaning packets were never actually leaving the host.
  - PacketDotNet now constructs the full `EthernetPacket → IPv4Packet → UdpPacket` chain and computes correct checksums automatically. A pool of 500 pre-built packets with randomized payloads, source ports, and IP IDs is cycled for high throughput.

- **TCP SYN Flood — Packets Dropped Pre-emptively by FortiGate (and Similar NGFWs)**
  - FortiGate's IPS engine classifies bare SYN packets (no TCP options, `DataOffset = 5`) as synthetic attack traffic and drops them before they reach the session table — hence the "pre-emptive" drops.
  - **TCP SYN options injected**: Every SYN packet now includes a Windows 10-style 12-byte options block (`MSS=1460 | NOP | WScale=8 | NOP | SACK-OK | padding`). The `InsertSynOptions()` helper inserts these bytes into the raw Ethernet frame after PacketDotNet builds it, then recomputes `DataOffset`, IP total length, IP checksum, and TCP checksum via proper 1's-complement logic.
  - **Source IP spoofing added** (`SpoofSourceIp = true`): Previously all SYN packets originated from the single attacker IP regardless of mode, allowing FortiGate to auto-block the source after a per-IP half-open session threshold. Source IPs are now randomized across the `/16` of the configured interface IP per packet, distributing load across thousands of apparent clients.
  - **Realistic TTL and window sizes**: TTL now alternates between 64 (Linux/macOS) and 128 (Windows) rather than random 64–128. Window size is picked from real OS values `{65535, 64240, 65495, 29200, 8192, 16384}` instead of a uniform random range.
  - Both `TcpSynFlood` and `TcpRoutedFlood` modes now always enable `RandomizeFlows`, `SpoofSourceIp`, and `AddTcpOptions`.

- **ICMP Flood — Send Rate Did Not Match Entered Mbps**
  - Replaced the raw ICMP socket with SharpPcap Layer-2 injection for consistency with UDP and TCP.
  - Root cause of rate mismatch: `OnPacketSent` passed only the 1408-byte ICMP payload (no headers) to the UI, while the rate controller budgeted at 1446-byte wire frames. Entering 10 Mbps resulted in the UI displaying ~9.74 Mbps while the wire actually carried 10 Mbps.
  - Each pool entry is now a full 1442-byte Ethernet frame. ICMP checksums are computed correctly without relying on the OS.
  - Dynamic burst cap (10 / 20 / 50 packets per loop iteration based on target rate) replaces the previous hardcoded cap of 5, preventing throughput starvation at high Mbps targets.

### Enhancements

- **Mbps Display Accuracy — FCS Correction Applied Globally**
  - The UI byte counter (`_totalBytesSent`) now adds 4 bytes per packet for the Ethernet FCS that the NIC appends on the wire. Previously, all attacks under-reported by ~0.3% because the L2 frame bytes were used without FCS.
  - After this fix: entered Mbps = displayed Mbps = wire Mbps for ICMP, UDP, and TCP floods.

---

## Version 2.3.0

### New Features
- **Reachability Tests Tab**: Comprehensive network reachability and path analysis capabilities
  - **Reachability & Path Analysis Wizard**: Guided wizard to analyze network reachability and path from your current location to target networks
    - Supports two analysis modes: "Remote Network Known" and "Boundary Only"
    - Configurable vantage point identification for multi-location testing
    - Automatic boundary gateway detection and vendor identification
    - ICMP and TCP reachability testing with detailed results
    - Firewall rule discovery for reachable hosts
    - Results stored locally and synced to Supabase for centralized analysis
  - **SNMP Walk Attack**: Automated SNMP walk operations for network device discovery
    - Tests 100 common SNMP community strings
    - Configurable target IP and SNMP port (default: 161)
    - Progress tracking with visual progress bar
    - Results displayed in dedicated results window
    - Perfect for authorized network security assessments
  - **Safety Disclaimer**: Prominent warning banner reminding users to only test authorized networks
    - Clear visual indicator with yellow warning banner
    - Emphasizes authorized use requirements
    - Professional safety messaging for compliance

### Enhancements
- **UI Layout & Spacing Improvements**: Comprehensive redesign based on 16px base unit system
  - **Global Layout**: Consistent edge padding and grid-based spacing throughout the application
    - Increased top margin from header to tabs for better visual separation
    - Consistent 16px-based spacing system applied across all UI elements
    - Improved breathing room between major sections
  - **Header Bar Refinements**: Enhanced spacing and visual hierarchy
    - Increased padding for better balance (16px vertical, 24px horizontal)
    - Improved spacing between metrics and Profile section (separator margin increased)
    - Dimmed metric labels (#9CA3AF) while keeping values bold (#111827) for better readability
    - Better visual separation between logo, metrics, icons, and status badge
  - **Tab Strip Improvements**: Better spacing and visual separation
    - Increased padding below tabs (16px) for clearer separation from content
    - Improved tab label padding for better touch targets
    - Clear visual distinction between tab row and card content
  - **Card Layout Enhancements**: Consistent spacing and improved readability
    - Increased card padding (20px) for better content breathing room
    - Consistent vertical gaps between cards (16px)
    - Improved card header spacing (16px margin below headers)
    - Enhanced form field spacing: labels 16px from fields, rows 12px apart
    - Better top and bottom padding within cards
  - **Security Logs Card**: Enhanced log area presentation
    - Increased padding around log content (12px) for better readability
    - Improved spacing between note input and log output sections
    - Better button alignment and spacing
  - **Button Row Improvements**: Better visual separation and alignment
    - Increased top margin (16px) from Attack Configuration card
    - Consistent horizontal spacing between buttons (12-16px)
    - Better alignment with card edges for visual consistency
  - **Advanced Settings Tab**: Applied same spacing improvements for consistency
    - All form fields use consistent 16px label spacing and 12px row spacing
    - Button rows match Basic Settings spacing
    - Improved card margins and padding throughout
  - **Reachability Tests Tab**: Professional spacing and layout
    - Enhanced yellow warning banner with increased padding (20px vertical, 16px horizontal)
    - Improved section spacing matching global vertical rhythm
    - Better SNMP Walk button alignment and spacing (12px between buttons)
    - Start button aligned with input fields for visual column consistency
- **Status Badge Logic Improvements**: Enhanced status indication for better clarity
  - **Running State**: Status badge now shows "Running" (red) when attack is actively executing
    - Clear visual indication that an attack is in progress
    - Red badge color matches the active danger state
  - **Idle State**: Status badge shows "Idle" (green) when stopped but in ATTACK MODE
    - Distinguishes between "Ready" (LAB MODE) and "Idle" (ATTACK MODE armed)
    - Better cognitive alignment: ATTACK MODE chip + Idle badge = armed but not running
  - **Ready State**: Status badge shows "Ready" (green) when in LAB MODE
    - Clear indication of safe, non-offensive mode
    - Consistent with LAB MODE badge display
  - **Visual Rule**: Only one strong red state at a time, matching actual danger level
    - Red = actively dangerous (attack running)
    - Green = safe or armed but idle
    - Better user understanding of current system state

### Bug Fixes
- **UI Scaling on Large Screens**: Fixed issue where Advanced Settings tab was scrollable even on large screens
  - Applied minimum 0.95 scale (5% reduction) to prevent content overflow
  - Ensures all tabs fit properly without scrolling on all screen sizes
  - Improved LayoutTransform application for consistent scaling
- **Multi-Monitor Detection**: Enhanced screen dimension detection for accurate scaling
  - Now uses Windows API (`MonitorFromWindow`, `GetMonitorInfo`) for precise monitor detection
  - Correctly identifies monitor dimensions when using HDMI or external displays
  - Prevents scaling issues when window is moved between monitors
- **Advanced Tab Card Margins**: Fixed duplicate margin issues in Advanced Settings tab
  - Removed redundant margins that were causing inconsistent spacing
  - CardStyle margins now properly applied throughout

### Technical Improvements
- **Multi-Monitor Support**: Enhanced `UIScalingService` with Windows API integration
  - Added `MONITORINFO` and `RECT` structs for detailed monitor information
  - Improved `GetScreenDimensionsForWindow` to use actual monitor dimensions
  - Better handling of multi-monitor setups and external displays
- **Status Badge Architecture**: Improved status badge update logic
  - All stop methods (`StopAttackAsync`, `StopArpSpoofingAsync`, `StopBroadcastAttackAsync`) now accept `isAdvancedMode` parameter
  - Proper state management based on current mode (LAB MODE vs ATTACK MODE)
  - Consistent status indication across all attack types
- **Spacing System Standardization**: Implemented 16px base unit system
  - All spacing now uses multiples of 16px for visual consistency
  - Easier maintenance and future UI updates
  - Professional, airy layout throughout the application
- **Reachability Service Integration**: Comprehensive reachability testing infrastructure
  - ICMP and TCP reachability testing with configurable timeouts
  - Firewall rule discovery for reachable hosts
  - Database integration for test result storage and synchronization
  - SNMP walk service with community string testing

---

## Version 2.2.7

### Bug Fixes
- **Database Migration on Fresh Install**: Fixed critical issue where fresh installations failed to sync with "no such column: HardwareId" error
  - Enhanced migration logic to properly handle Ports table column additions
  - Migration now runs automatically before any Ports table queries
  - Improved error handling for column existence checks
  - Resolves sync failures on fresh laptop installations
- **Settings Window Emoji Display**: Fixed corrupted emoji characters in Settings window
  - Replaced all corrupted emoji characters with reliable text alternatives
  - Settings window now displays correctly without encoding issues
  - Improved visual consistency across all UI elements
- **Supabase URL Display**: Fixed incorrect hardcoded Supabase URL in Settings window
  - URL now displays dynamically from actual configuration
  - Shows correct Supabase endpoint instead of placeholder URL
  - Better transparency for users viewing connection settings

### Enhancements
- **Database Migration Safety**: Improved migration reliability and error handling
  - Migration checks run before critical database queries
  - Better handling of edge cases (table doesn't exist, columns already exist)
  - More robust error recovery during migration process
  - Enhanced logging for troubleshooting migration issues
- **UI Text Alternatives**: Replaced problematic emoji characters with text-based indicators
  - Uses [OK], [X], [!], [?], [i] for status indicators
  - More reliable cross-platform rendering
  - Better accessibility for users with emoji rendering issues

### Technical Improvements
- **Migration Architecture**: Enhanced database migration system
  - Added `EnsureMigrationsAsync` method for on-demand migration checks
  - Automatic migration verification before Ports table queries
  - Better separation of concerns between table creation and migration
  - Improved error handling with graceful fallbacks
- **Settings Window Code Quality**: Improved Settings window implementation
  - Dynamic Supabase URL binding from configuration
  - Better error handling for configuration display
  - Cleaner code structure for maintainability

---

## Version 2.2.6

### Bug Fixes
- **Update Check Version Comparison**: Fixed issue where update check was not correctly identifying the latest version from database
  - Now performs proper semantic version comparison instead of relying solely on creation date
  - Correctly identifies highest version number even if releases are not in chronological order
  - Resolves issue where newer versions in database were not detected as available updates
- **Tab Navigation Fix**: Fixed bug where acknowledging disclaimer in Advanced Settings tab would incorrectly switch back to Firewall & Networks tab
  - Advanced Settings tab now remains selected after disclaimer acknowledgment
  - Proper tab state management prevents unintended navigation
  - Improved user experience when accessing advanced features
- **UDP Unicast Rate Limiting**: Fixed issue where UDP unicast attacks could not reach target Mbps rates
  - Increased dynamic burst limits based on target rate (10/20/50 packets per iteration)
  - Improved throughput for high-rate UDP attacks
  - Better rate control for medium and high bandwidth targets
- **Modbus TCP Read Rate Limiting**: Fixed issue where Modbus/TCP Read Requests attacks could not reach target Mbps rates
  - Increased dynamic burst limits based on target rate (10/20/50 packets per iteration)
  - Improved throughput for high-rate Modbus/TCP attacks
  - Better rate control matching TCP flood performance

### Enhancements
- **Update Check Logging**: Reduced verbose logging during update checks
  - Removed "Querying release database" and "Found X release(s)" messages
  - Only displays update check results when update is available or errors occur
  - Cleaner log output with less noise
- **Error Handling**: Improved error detection and reporting for update checks
  - Better RLS (Row Level Security) policy violation detection
  - Clearer error messages for database connection issues
  - Enhanced logging for troubleshooting update check problems

### Technical Improvements
- **Version Comparison Algorithm**: Enhanced version comparison to use semantic versioning
  - Properly compares major.minor.build version numbers
  - Handles version strings correctly regardless of database ordering
  - More reliable update detection across all version formats
- **Rate Limiting Optimization**: Improved burst size calculation for UDP and Modbus TCP attacks
  - Dynamic burst limits adapt to target Mbps rate
  - Better performance at high rates (>50 Mbps)
  - Consistent rate control across all attack types

---

## Version 2.2.5

### New Features
- **Modbus/TCP Flood Attack Preset**: Added new ICS/OT attack preset for authorized testing environments
  - **Modbus/TCP Flood (Read Requests)**: TCP-based flood attack with syntactically valid Modbus/TCP payloads
    - Generates valid Modbus/TCP Application Data Unit (ADU) packets
    - Default destination port: 502 (standard Modbus/TCP port)
    - Function Code: 0x03 (Read Holding Registers - non-destructive)
    - Unit ID: 1 (configurable, default 1)
    - Transaction ID randomization for each packet
    - Read-only requests by default (safe for testing)
  - **Accurate Rate Control**: Reuses proven TCP flood rate limiting logic for precise Mbps matching
    - 1:1 Mbps accuracy matching target bandwidth
    - Byte-budget rate control ensures consistent performance
    - Same rate limiting engine as TCP SYN flood for reliability
  - **ICS/OT Testing Focus**: Designed specifically for Industrial Control Systems and Operational Technology testing
    - Clearly marked as non-destructive (read-only requests)
    - Suitable for authorized lab environments
    - Proper logging with Modbus-specific information
- **Update Notification Badge**: Visual indicator on About button when updates are available
  - Red alert badge appears on the About icon when a newer version is detected
  - Badge automatically updates based on version check results
  - Provides immediate visual feedback for available updates without opening the About dialog
- **Port Scan Optimization**: Improved port scanning behavior to separate discovery from banner grabbing
  - Normal port scans (All Ports, Range) now only show open ports and service names
  - Banner grabbing only occurs in Selected mode (intense scan with explicit banner grabbing)
  - Faster port discovery without the overhead of banner grabbing for quick scans

### Enhancements
- **Advanced Attack Menu**: Added Modbus/TCP Flood to Advanced Attacks dropdown (authorized personnel only)
  - Requires password validation to access
  - Automatically sets default port to 502 when selected
  - Integrated with existing rate limiting and logging systems
- **Attack Logging**: Enhanced logging for Modbus/TCP attacks
  - Displays protocol as "TCP (Modbus/TCP)"
  - Shows function code (0x03) and unit ID in summary
  - Clearly indicates non-destructive nature of read requests
  - Includes all standard attack metrics (Mbps, packets sent, etc.)
- **Cloud Sync Icon**: Changed alert icon to cloud icon (☁️) for better visual clarity and consistency
- **About Button Icon**: Changed About button icon to information icon (ℹ️) to distinguish it from other buttons
- **Port Data Separation**: Improved separation of port data between assets and ports tables during cloud sync
  - Port numbers are stored in `assets.ports` column as summary (e.g., "80/TCP, 443/TCP")
  - Full port details including banners are stored in separate `ports` table
  - Ensures proper data organization and efficient querying
- **Emoji Display**: Fixed all emoji encoding issues throughout the application
  - Correct Unicode emojis now display properly in log messages
  - Improved visual feedback with properly rendered emoji characters
  - Enhanced user experience with clear visual indicators

### Bug Fixes
- **Fixed Emoji Encoding**: Resolved corrupted emoji characters in log output
  - Replaced all corrupted emoji characters with correct Unicode representations
  - Fixed emoji display in AttackLogger (ℹ️, ❌, ⚠️, ✅, etc.)
  - Corrected emoji display in MainWindow validation messages (🔓, etc.)
  - Fixed emoji display in NetworkScan and NetworkStorm log messages
- **Port Sync Separation**: Fixed issue where ports and banners were not properly separated during cloud sync
  - Port numbers now correctly stored in `assets.ports` column (summary only)
  - Banner information correctly stored in `ports` table with full details
  - Database trigger automatically updates `assets.ports` when `ports` table changes
- **Icon Consistency**: Fixed icon confusion between About and Cloud Sync buttons
  - About button now uses information icon (ℹ️)
  - Cloud Sync button uses cloud icon (☁️)
  - Improved visual distinction between different UI elements

### Technical Improvements
- **ModbusTcpFlood Class**: New dedicated class for Modbus/TCP packet generation
  - Builds proper Modbus/TCP ADU structure (Transaction ID, Protocol ID, Length, Unit ID, PDU)
  - Supports configurable function codes and unit IDs
  - Proper big-endian byte ordering for Modbus protocol compliance
  - Random transaction IDs for each packet to simulate realistic traffic
- **NetworkStorm Integration**: Added `StartModbusTcpAttackAsync` method for seamless integration
- **AttackLogger Enhancement**: Added `StartModbusTcpAttack` method for Modbus-specific logging
- **Update Check Integration**: Enhanced MainWindow with periodic update checking
  - Update check timer runs every 30 minutes
  - Automatic badge visibility updates based on update availability
  - Improved update detection reliability
- **Emoji Encoding Standardization**: Standardized all emoji usage to proper Unicode characters
  - Replaced all corrupted characters with correct Unicode emojis
  - Improved cross-platform compatibility for emoji display
  - Enhanced log readability with properly rendered visual indicators
- **Database Schema Alignment**: Ensured proper alignment between local and cloud database schemas
  - Port separation logic correctly implemented in both DatabaseService and SupabaseSyncService
  - Database triggers properly configured for automatic `assets.ports` updates
  - Improved data consistency between local SQLite and Supabase databases
- **Port Scan Logic**: Optimized banner grabbing to only occur in Selected mode
  - Normal scans (All, Range) skip banner grabbing for faster discovery
  - Selected mode performs full banner grabbing with extended timeouts
  - Improved scan performance for large port ranges

---

## Version 2.2.4

### New Features
- **Offline Banner Grabbing Enhancements**: Comprehensive improvements to banner grabbing that work entirely offline without internet connectivity
  - **Banner Fingerprinting**: Intelligent parsing of raw banners into human-readable labels
    - HTTP/HTTPS: Extracts status lines and Server headers (e.g., "HTTP/1.1 200 OK | Server: nginx/1.18.0")
    - SSH: Labels SSH banners with version information
    - Mail Services: Identifies SMTP/POP3/IMAP banners
    - MySQL: Detects and labels MySQL service banners
    - Generic Fingerprinting: Recognizes common services (OpenSSH, nginx, Apache, IIS, Postfix, Exim, Dovecot, vsftpd, ProFTPD, Pure-FTPd)
  - **OS and Service Hints**: Automatically derives operating system and service information from banners
    - OS Detection: Identifies Linux (Ubuntu, Debian, CentOS, RHEL, Fedora, SUSE, Arch), Windows (IIS, Windows, Win32), and BSD variants
    - Service Detection: Recognizes HTTP(S), SSH, SMTP, POP3, IMAP, FTP, MySQL, PostgreSQL, SMB/NetBIOS, RDP
    - All hints are stored per-asset and displayed in the UI for quick reference
  - **Protocol-Specific Timeouts**: Intelligent timeout management based on protocol characteristics
    - Fast protocols (HTTP, SSH, FTP): 1000ms maximum
    - Mail protocols (SMTP, POP3, IMAP): 2000ms minimum for slower mail servers
    - Database protocols (MySQL, PostgreSQL): 1500ms maximum
    - TLS protocols (HTTPS, IMAPS, POP3S): 2000ms minimum for handshake completion
  - **Retry Logic**: Automatic retry for server-first protocols (FTP, SSH, SMTP, IMAP, POP3, MySQL, PostgreSQL) when initial read returns empty
  - **Banner Cap**: Limits banner grabbing to 20 banners per host to prevent stalling on large port scans
  - **Enhanced Binary Protocol Detection**: Improved identification of binary protocols
    - SMB: Distinguishes between SMBv1 (legacy/vulnerable) and SMBv2/3
    - RDP: Validates TPKT packet structure for confirmed RDP detection
    - RPC: Enhanced DCE/RPC endpoint mapper identification
- **Version Checking and Update Notification System**: Automatic update detection and notification
  - **Release Database Integration**: Connects to Supabase releases table to check for latest version
  - **Update Status Display**: Shows version status in About dialog
    - "Latest" (green) when running the latest version
    - "Not Latest" (red) when an update is available
    - "Cloud" (gray) when offline or Supabase not configured
  - **Update Notification Banner**: Displays update information when newer version is available
  - **Direct Download Link**: "Download Update" button redirects to releases page for easy access
  - **Online/Offline Detection**: Automatically detects internet connectivity for update checking
  - **Version Comparison**: Intelligent semantic version comparison (e.g., 2.2.3 vs 2.2.4)

### Enhancements
- **Port Details Table Scrolling**: Fixed scrolling behavior for port details table
  - Port details container now has fixed height (350px) to prevent covering footer buttons
  - DataGrid scrolling enabled for both vertical and horizontal directions
  - Footer buttons (Back, Cancel Scan, Sync Assets, Export to Excel, Close) remain accessible even with many port results
  - Improved layout constraints to ensure proper UI element visibility
- **Banner Grabbing Performance**: Optimized banner grabbing for better performance
  - Protocol-specific timeouts reduce unnecessary waiting
  - Retry logic improves success rate for slow-responding services
  - Banner cap prevents performance degradation on large scans
- **Offline Operation**: All banner improvements work completely offline
  - No internet connectivity required for banner fingerprinting
  - OS and service hints derived purely from captured banners
  - Perfect for air-gapped environments and CTF scenarios

### Bug Fixes
- Fixed port details table covering footer buttons after full port scans
- Corrected DataGrid scrolling behavior to properly constrain within container
- Improved layout constraints to prevent UI elements from being hidden

### Technical Improvements
- Added `FingerprintBanner` method for intelligent banner parsing
- Implemented `UpdateOsAndServiceHints` for automatic OS/service detection
- Added `GetTimeoutForPort` for protocol-specific timeout management
- Enhanced `GetBinaryProtocolHint` with improved SMB and RDP detection
- Created `ReleaseEntry` database model for version tracking
- Implemented `UpdateCheckService` for automatic update detection
- Added `GetSupabaseClient` method to `SupabaseSyncService` for update checking
- Improved `AboutWindow` with version status display and update notification

---

## Version 2.2.3

### New Features
- **Simplified Network Scan Mode**: Enhanced simple scan mode to focus on discovering alive devices on the network without port scanning overhead
  - Simple scan mode now only performs ICMP ping to detect active devices
  - No port scanning in simple mode - faster and more efficient for basic network discovery
  - Device name resolution with intelligent fallback to IP address for offline use
- **Separate Ports Database Table**: Implemented dedicated database table for port scan results with proper foreign key relationships
  - Ports are now stored separately from assets, enabling better data organization and querying
  - Each port entry includes: Port number, Protocol, Service name, Banner information, and scan metadata
  - Improved data integrity with foreign key constraints and cascade delete support
- **Enhanced Port Display**: Redesigned port details view with dedicated DataGrid for better visualization
  - Separate ports table below main results grid showing all port details
  - Improved banner display with monospace font and text wrapping
  - Auto-selection of first asset with ports when scan completes
  - Port count indicator with visual feedback

### Enhancements
- **Network Scan Improvements**:
  - Changed "Hostname" field to "Name" for better clarity and offline usability
  - Vendor information is now always populated when MAC address is available (uses local OUI database)
  - Device name is always populated - uses hostname resolution when available, falls back to IP address for offline reference
  - Improved device name resolution with multiple fallback methods (DNS, NetBIOS, ARP table)
  - All scan results are automatically saved to local database for offline access
- **Port Scan Mode Enhancements**:
  - Renamed port scan modes for clarity: "Common Ports", "All Common Ports", "Range", "Selected (Intense + Banners)"
  - Selected mode now auto-populates with ports discovered in previous scans
  - "Use Discovered Ports" button to quickly populate Selected mode with found ports
  - Selected mode performs very intense scanning with extended banner grabbing (3-second timeout)
- **Banner Grabbing Improvements**:
  - Banner grabbing now enabled for all ports in intense scan mode (not just selected ports)
  - Added specific probes for additional ports: 135 (RPC), 139 (NetBIOS), 445 (SMB), 3389 (RDP)
  - Improved banner reading with binary data handling (hex display for non-ASCII responses)
  - Empty banner handling with informative messages instead of blank cells
- **Asset Update and Re-sync Logic**:
  - Assets are now updated (not duplicated) when scanning the same IP addresses
  - When ports are added to existing assets, the asset is automatically marked as unsynced
  - Ports are updated (not duplicated) when scanning the same ports again
  - Enables workflow: Simple scan → Sync → Port scan → Re-sync with port data
- **Better Offline Support**: Device names and vendor information are stored locally, allowing you to reference scanned devices even when offline
- **Window Size Improvements**: Increased default window size to 1600x900 for better visibility of scan results

### Bug Fixes
- Fixed device name resolution to always provide a value (hostname or IP address) for offline use
- Improved vendor lookup reliability in simple scan mode
- Enhanced error handling for MAC address resolution
- Fixed banner grabbing to work correctly for all ports in intense scan mode
- Corrected empty banner display to show informative message instead of blank cells
- Fixed asset duplication when re-scanning the same IP addresses
- Improved port update logic to prevent duplicate port entries

### Technical Improvements
- Refactored NetworkAsset model to use "Name" instead of "Hostname" for better semantic clarity
- Improved device name fallback logic to ensure offline usability
- Enhanced vendor lookup to always attempt resolution when MAC address is available
- Added PortEntry database model with proper Supabase integration
- Implemented asset lookup and update logic in DatabaseService
- Enhanced SavePortAsync to handle port updates and asset re-sync marking
- Improved database schema with ports table and proper foreign key relationships

---

## Version 2.2.2

### New Features
- **Advanced Settings Password Protection**: Enhanced security with password-protected access to advanced attack features. Password validation persists across sessions for improved user experience.
- **Disclaimer Dialog**: Added mandatory disclaimer acknowledgment for Advanced Settings to ensure users understand the authorized use requirements.
- **Custom Font Size Control**: Users can now customize font size (8-24px) for both left and right panels, improving accessibility and readability across different screen sizes and DPI settings.
- **Improved Authentication Feedback**: Replaced modal dialogs with inline feedback for password validation, providing a smoother user experience with visual indicators for success and failure states.
- **Database Schema Updates**: Added ports table to Supabase schema for separate port data storage with foreign key relationships

### Enhancements
- **UI Responsiveness**: Improved UI scaling and layout to prevent scrolling issues on smaller screens. All input fields now properly center text vertically.
- **Tab Navigation**: Enhanced tab switching reliability with improved event handling, preventing unresponsive states and ensuring correct navigation between Basic Settings, Advanced Settings, and Firewall & Networks tabs.
- **Rate Limiting Fixes**: Fixed rate limiting calculations for advanced attacks (NMEA 0183 UDP Flood, Ethernet attacks) to accurately match target Mbps settings.
- **Dialog Design Consistency**: Standardized all dialogs to match application branding with consistent button patterns and visual styling.
- **Toast Notifications**: Added non-blocking toast notifications for successful operations, reducing UI interruption.

### Bug Fixes
- Fixed Ethernet Multicast logging to correctly display "Multicast IP" and "Multicast MAC" information
- Fixed log file location selection error related to Windows API marshaling
- Corrected rate calculation for NMEA 0183 UDP attacks to match target bandwidth
- Fixed Advanced Settings badge display (LAB MODE → ATTACK MODE)
- **Fixed tab switching issues**: Resolved unresponsive Advanced Settings tab and incorrect tab navigation after disclaimer acknowledgment
  - Added re-entrancy protection to prevent event handler conflicts during rapid tab switching
  - Improved previous tab tracking to correctly return users to their originating tab when disclaimer is not acknowledged
  - Fixed issue where acknowledging disclaimer would sometimes navigate to wrong tab (Basic or Firewall)
  - Enhanced tab change event handling to prevent race conditions and UI freezing

### Technical Improvements
- Removed deprecated `TcpFloodRouted` class in favor of unified `TcpFlood` implementation
- Improved password validation token management with secure session persistence
- Enhanced error handling for network operations
- Improved tab navigation logic with proper event handling and state management
- Added re-entrancy guards to prevent UI event conflicts

---

## Version 2.2.1

### New Features
- **NMEA 0183 UDP Attack Presets**: Added two new UDP-based attack presets for NMEA 0183 navigation data:
  - NMEA 0183 (UDP Unicast): Standard unicast UDP flood with NMEA-style ASCII payloads
  - NMEA 0183 (UDP Multicast): Multicast UDP flood with default multicast IP (239.192.0.1) and TTL=1
- **Unified TCP Flood Implementation**: Refactored TCP flood to support routing-aware options (payload, randomization, routing mode) with automatic routing detection
- **TCP Routed Mode Calibration**: Implemented calibration step for routed TCP mode to measure maximum packets per second and dynamically adjust payload size

### Enhancements
- Improved MAC address resolution for multicast traffic
- Enhanced logging for multicast attacks with proper IP and MAC address display
- Better handling of interface selection for multicast attacks using unicast IP addresses
- Improved NMEA attack rate limiting to accurately match target Mbps

### Bug Fixes
- Fixed TCP flood routing detection logic
- Corrected payload size calculations for routed TCP attacks
- Improved error handling for network interface selection
- Fixed NMEA 0183 UDP attack rate calculation to properly match target bandwidth

---

## Version 2.2.0

### Major Features
- **Firewall & Networks Tab**: New tab for network reachability testing and firewall rule discovery
  - ICMP and TCP reachability testing
  - Firewall rule discovery for reachable hosts
  - Port scanning with detailed results
  - Integration with attack configuration (Use as Attack Target feature)
- **Enhanced Network Scanning**: Improved network discovery with better host detection and port analysis
- **Network Scan Window Redesign**: Completely redesigned network scan interface with better organization and visibility

### Enhancements
- **UI Scaling Improvements**: 
  - Star-sized columns for better responsive layout (50:50 split)
  - Removed fixed widths on containers
  - Improved vertical alignment for all input fields
  - Better handling of different screen sizes and resolutions
  - Increased default window size for better data visibility
- **Attack Type Organization**: Reorganized attack types with clearer categorization in Advanced Settings
- **Logging Improvements**: Enhanced attack logging with more detailed information and better formatting
- **Network Scan Display**: Improved results grid with better column sizing and port count display

### Bug Fixes
- Fixed UI scrolling issues on smaller screens
- Corrected column width calculations in configuration cards
- Improved text centering in input fields
- Fixed layout issues with TabControl and ScrollViewer
- Fixed Ethernet Multicast logging to correctly display IP and MAC information

### Technical Improvements
- Refactored UI layout structure for better maintainability
- Improved resource management for network operations
- Enhanced error handling and user feedback
- Better database integration for network scan results

---

## Version 2.1.2

### New Features
- **Enhanced Network Scanning**: Improved network discovery capabilities with better host detection
- **Port Scanning Enhancements**: Better port scanning with improved accuracy and performance

### Enhancements
- **Network Operations**: 
  - Improved MAC address resolution reliability
  - Enhanced hostname resolution with multiple fallback methods
  - Better handling of network interface selection
- **Attack Configuration**: Improved validation and error messages for attack parameters
- **UI Improvements**: Better visual feedback for network operations

### Bug Fixes
- Fixed network interface enumeration issues on some systems
- Corrected MAC address resolution failures
- Improved error handling for network timeouts
- Fixed port scanning accuracy issues

### Technical Improvements
- Code cleanup and refactoring
- Improved exception handling for network operations
- Better resource disposal patterns
- Enhanced logging for network scan operations

---

## Version 2.1.1

### New Features
- **About Dialog Redesign**: 
  - Added "Application Info" section
  - Grouped features into logical subgroups
  - Added copyright and website footer information
  - Improved visual hierarchy and readability

### Enhancements
- **Settings Window Improvements**: Enhanced settings interface with better organization
- **Network Interface Selection**: Improved interface selection for network operations
- **Attack Configuration**: Better validation and error messages for attack parameters

### Bug Fixes
- Fixed font size application across different UI elements
- Corrected settings persistence issues
- Fixed network interface enumeration on some systems
- Resolved memory leaks in long-running attack operations

### Technical Improvements
- Code cleanup and refactoring
- Improved exception handling
- Better resource disposal patterns

---

## Version 2.1.0

### Major Features
- **Advanced Attack Modes**: 
  - Enhanced Ethernet Flood attacks (Unicast, Multicast, Broadcast)
  - Improved TCP SYN Flood with routing support
  - Better UDP Flood implementation
  - ICMP Flood enhancements
- **Network Discovery**: 
  - Enhanced network scanning capabilities
  - Improved hostname resolution
  - Better MAC address resolution with ARP fallback
- **Settings Management**: 
  - Improved settings persistence
  - Better configuration validation
  - Enhanced user preferences storage

### Enhancements
- **UI/UX Improvements**:
  - Better visual feedback for attack status
  - Improved button states and interactions
  - Enhanced log display with better formatting
  - Better error message presentation
- **Performance Optimizations**:
  - Optimized packet generation for high-rate attacks
  - Improved memory usage during long-running attacks
  - Better thread management for concurrent operations
- **Network Operations**:
  - Improved gateway detection
  - Better handling of routed vs. local traffic
  - Enhanced multicast support

### Bug Fixes
- Fixed memory leaks in attack operations
- Corrected rate limiting calculations
- Fixed UI freezing during high-rate attacks
- Resolved issues with network interface selection
- Fixed logging inconsistencies

### Technical Improvements
- Refactored attack engine architecture
- Improved async/await patterns
- Better cancellation token handling
- Enhanced error recovery mechanisms

---

## Version 2.0.0

### Major Release - Complete Rewrite

### New Architecture
- **Modern WPF Application**: Complete rewrite using .NET 8.0 and WPF
- **MVVM Pattern**: Improved code organization with better separation of concerns
- **Service-Oriented Design**: Modular architecture with dedicated services for different functionalities

### Core Features
- **Basic Attack Modes**:
  - TCP SYN Flood
  - UDP Flood
  - ICMP Flood
  - ARP Spoofing
- **Advanced Attack Modes**:
  - Ethernet Flood (Unicast, Multicast, Broadcast)
  - Custom packet generation
  - Advanced routing options
- **Network Utilities**:
  - Network scanning
  - Port scanning
  - Hostname resolution
  - MAC address resolution
- **Logging & Reporting**:
  - Real-time attack logging
  - Database integration
  - Export capabilities
  - Attack history tracking

### UI/UX
- **Modern Interface**: Clean, professional design with intuitive navigation
- **Tabbed Interface**: Organized into Basic Settings, Advanced Settings, and utility tabs
- **Real-time Status**: Live attack status and statistics
- **Comprehensive Logging**: Detailed attack logs with timestamps and metrics

### Technical Foundation
- **.NET 8.0**: Latest framework with improved performance
- **PacketDotNet & SharpPcap**: Professional packet manipulation libraries
- **NLog Integration**: Comprehensive logging framework
- **SQLite Database**: Local data storage for attack history
- **Supabase Integration**: Cloud-based data synchronization

### Security & Compliance
- **Administrator Privileges**: Proper privilege handling for network operations
- **User Authorization**: Built-in authorization mechanisms
- **Audit Logging**: Comprehensive logging for compliance

### Installation
- **Windows Installer**: Professional Inno Setup installer
- **Self-Contained Deployment**: No external dependencies required
- **Automatic Updates**: Upgrade detection and installation

---

## Upgrade Notes

### From 2.1.x to 2.2.2
- Password protection is now required for Advanced Settings
- Font size customization is available in Settings
- Disclaimer acknowledgment is required when accessing Advanced Settings

### From 2.0.x to 2.2.2
- Settings format has changed; some preferences may need to be reconfigured
- New firewall and network analysis features are available
- Improved UI scaling may require window size adjustments

### General Upgrade Instructions
1. Backup your current configuration (if applicable)
2. Uninstall previous version (optional - installer handles upgrades automatically)
3. Run the new installer
4. Review and acknowledge the disclaimer when accessing Advanced Settings
5. Configure your preferred font size in Settings

---

## System Requirements

- **Operating System**: Windows 10/11 (64-bit)
- **.NET Runtime**: Included (self-contained deployment)
- **Privileges**: Administrator rights required for network operations
- **Network**: Active network interface required
- **Hardware**: Minimum 2GB RAM, 100MB free disk space

---

## Known Issues

- Some antivirus software may flag the application due to network packet manipulation capabilities
- Rate limiting may vary slightly from target Mbps on slower systems
- Font size changes require application restart to take full effect

**Note**: All known issues from previous versions have been resolved in version 2.2.2.

---

## Support

For issues, questions, or feature requests, please contact the development team or visit the project repository.

---

**Copyright(C) SeaNet Co., Ltd. All right reserved**

