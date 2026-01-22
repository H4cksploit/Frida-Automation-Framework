🚀 **Frida Automation Framework**

A powerful, user-friendly GUI tool for automating Frida script execution on Android devices with Windows compatibility and CodeShare integration.

📖 **Overview**

Frida Automation Framework simplifies mobile application security testing by providing a comprehensive GUI interface for Frida scripting. It eliminates the need for manual command-line operations, making dynamic instrumentation accessible to both beginners and experts.

✨ **Features**

🎯 **Core Features**

✅ Auto frida-server Installation - Automatically detects device architecture and installs correct frida-server

✅ Windows Compatible - Optimized for Windows OS with proper path handling

✅ Frida CodeShare Integration - Direct access to community scripts

✅ Root Detection - Automatic root status checking

✅ Script Organizer - Manage local and online scripts efficiently

✅ Real-time Output - Live monitoring of script execution

✅ Device Management - Auto-detect and manage

🛠️ **Technical Features**

✅ Multi-path Support - Install frida-server to different locations

✅ ADB Management - Built-in ADB tools and reconnect functionality

✅ Attach Mode - Attach to running apps

✅ Spawn Mode - Launch fresh

✅ Progress Tracking - Visual progress bars for operations

✅ Error Handling - Comprehensive error messages and solutions

✅ Export Capabilities - Save execution logs for analysis


🚀 **Quick Start**

Prerequisites

Python 3.7 or higher

ADB (Android Debug Bridge)

USB Debugging enabled on Android device

Frida-tools (optional - can be installed via GUI)

**Installation**

Clone the repository:

```bash

git clone https://github.com/H4cksploit/Frida-Automation-Framework.git
cd Frida-Automation-Framework
```
Install dependencies:

```bash
pip install -r requirements.txt
```
Run the application:

```bash
python frida-run.py
```
📋**Usage Guide:**

Complete Workflow

Step 1: Connect Device

-->Enable USB Debugging on Android device

-->Connect via USB cable

-->Click "Detect Devices" or press Ctrl+R

Step 2: Install Frida Server

-->Select your device from the list

-->Click "Auto Setup Device" or press Ctrl+A

-->Framework automatically:

-->Detects device architecture

-->Downloads correct frida-server

-->Pushes to /data/local/tmp/

-->Sets permissions

-->Starts the server

Step 3: Load Scripts

-->Local Scripts: Click "Scan" (Ctrl+S) to load from:

-->scripts/ folder

-->frida_scripts/ folder

-->Desktop/Frida_Scripts/

-->CodeShare Scripts: Enter author/script format:

```text
pcipolloni/universal-android-ssl-pinning-bypass
hluwa/strongR-frida-android
dki/ios-monitor
```
Step 4: Execute Script

-->Select target application

-->Choose execution mode:

-->Attach - Inject into running app

-->Spawn - Launch fresh instance (requires root)

-->Click "Execute Script" (Ctrl+E)

-->Monitor real-time output

🏗️ **Architecture**
```text
Frida Automation Framework
├── GUI Layer (Tkinter)
│   ├── Device Management Panel
│   ├── Script Management Panel
│   ├── Execution Control Panel
│   └── Output Terminal
├── Service Layer
│   ├── FridaServerInstaller
│   ├── CodeShare Manager
│   └── ADB Manager
└── Integration Layer
    ├── Frida CLI Integration
    ├── ADB Integration
    └── CodeShare API Integration
```

**Custom Installation Paths**

The framework supports multiple installation paths:

```
FRIDA_SERVER_PATHS = [
    "/data/local/tmp/frida-server",  # Default
    "/sdcard/frida-server",          # SD Card
    "/system/bin/frida-server",      # System (root)
]
```
**CodeShare Integration**
```
# Direct usage of community scripts
frida -U --codeshare author/script-name -p PID
```
**Manual Operations**
Menu → Install → Manual Server Push - Custom frida-server installation

Menu → Device → ADB Shell - Direct ADB access

Menu → Tools → Frida Console - Interactive Frida REPL

📁 **Project Structure**
```
frida-automation-framework/
├── frida_auto.py              # Main application
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── scripts/                   # User scripts folder
│   ├── ssl_bypass.js         # SSL pinning bypass
│   ├── root_detection.js     # Root detection bypass
│   └── custom_hooks.js       # User custom scripts
├── samples/                   # Sample scripts
│   ├── android/
│   └── ios/
└── docs/                     # Documentation
    ├── workflow.md
    └── troubleshooting.md

```

🌟 **Use Cases**
Dynamic analysis of mobile applications

Bypassing security controls

Vulnerability discovery

<p align="center"> Made with ❤️ for the security community </p><p align="center"> If you find this tool useful, please give it a ⭐ on GitHub! </p>
