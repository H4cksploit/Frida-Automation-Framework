#!/usr/bin/env python3
"""
Frida Automation Framework
Version: 3.5
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
import subprocess
import threading
import os
import sys
import json
import time
import re
import webbrowser
from pathlib import Path
import tempfile
import requests
import platform

# ============================================================================
# CONFIGURATION - WINDOWS COMPATIBLE
# ============================================================================

class Config:
    """Configuration settings for Windows"""
    SCRIPT_DIRS = [
        "scripts",
        "frida_scripts",
        Path.home() / "Desktop" / "Frida_Scripts"
    ]
    
    # Frida server paths - Multiple options for Android
    FRIDA_SERVER_PATHS = [
        "/data/local/tmp/frida-server",  # Default temporary location
        "/sdcard/frida-server",          # SD card (no root needed)
        "/system/bin/frida-server",      # System binary (root needed)
    ]
    
    # Selected path
    SELECTED_SERVER_PATH = "/data/local/tmp/frida-server"
    
    # Colors
    COLORS = {
        'bg': '#1e1e1e',
        'fg': '#ffffff',
        'accent': '#007acc',
        'success': '#4CAF50',
        'warning': '#FF9800',
        'error': '#f44336',
        'card_bg': '#2d2d30',
        'terminal_bg': '#0c0c0c',
        'terminal_fg': '#00ff00',
        'codeshare_bg': '#1a3c40',
        'install_bg': '#4a148c'
    }

# ============================================================================
# CUSTOM WIDGETS
# ============================================================================

class ModernButton(tk.Button):
    """Modern styled button"""
    def __init__(self, parent, text, command, **kwargs):
        bg = kwargs.pop('bg', Config.COLORS['accent'])
        fg = kwargs.pop('fg', Config.COLORS['fg'])
        font = kwargs.pop('font', ('Segoe UI', 10, 'bold'))
        
        super().__init__(parent, text=text, command=command,
                        bg=bg, fg=fg, font=font,
                        relief='flat', bd=0, cursor='hand2',
                        activebackground='#005a9e',
                        activeforeground=Config.COLORS['fg'],
                        **kwargs)
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        
    def on_enter(self, e):
        self['bg'] = '#005a9e'
        
    def on_leave(self, e):
        self['bg'] = Config.COLORS['accent']

class ModernFrame(tk.Frame):
    """Modern styled frame"""
    def __init__(self, parent, **kwargs):
        bg = kwargs.pop('bg', Config.COLORS['bg'])
        super().__init__(parent, bg=bg, **kwargs)

# ============================================================================
# FRIDA SERVER INSTALLER - WINDOWS COMPATIBLE
# ============================================================================

class FridaServerInstaller:
    """Handle frida-server installation on device - Windows Compatible"""
    
    @staticmethod
    def get_os_type():
        """Get operating system type"""
        return platform.system()  # Returns 'Windows', 'Linux', 'Darwin'
    
    @staticmethod
    def get_device_architecture(device_serial=None):
        """Get device architecture"""
        try:
            if device_serial:
                cmd = f"adb -s {device_serial} shell getprop ro.product.cpu.abi"
            else:
                cmd = "adb shell getprop ro.product.cpu.abi"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            arch = result.stdout.strip().lower()
            
            # Map to frida architecture names
            arch_map = {
                'armeabi-v7a': 'arm',
                'arm64-v8a': 'arm64',
                'x86': 'x86',
                'x86_64': 'x86_64'
            }
            
            for key, value in arch_map.items():
                if key in arch:
                    return value
            
            return 'arm64'  # Default for modern Android
        except:
            return 'arm64'
    
    @staticmethod
    def get_frida_version():
        """Get installed frida version on PC"""
        try:
            result = subprocess.run("frida --version", shell=True, 
                                  capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return None
    
    @staticmethod
    def get_latest_frida_release():
        """Get latest frida release from GitHub"""
        try:
            response = requests.get(
                "https://api.github.com/repos/frida/frida/releases/latest",
                timeout=10
            )
            release = response.json()
            return release['tag_name'].replace('frida-', '')
        except:
            # Fallback to a known working version
            return "17.1.2"
    
    @staticmethod
    def download_frida_server(version, architecture):
        """Download frida-server for given version and architecture"""
        try:
            # Try different URL patterns
            url_patterns = [
                f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{architecture}.xz",
                f"https://github.com/frida/frida/releases/download/frida-{version}/frida-server-{version}-android-{architecture}.xz",
                f"https://github.com/frida/frida/releases/download/{version}/frida-server-{version}-android-{architecture}"
            ]
            
            for url in url_patterns:
                try:
                    print(f"Trying: {url}")
                    response = requests.get(url, stream=True, timeout=30)
                    
                    if response.status_code == 200:
                        print(f"Download successful from: {url}")
                        return response.content
                    else:
                        print(f"Failed with status: {response.status_code}")
                except Exception as e:
                    print(f"Error downloading from {url}: {e}")
                    continue
            
            raise Exception("All download attempts failed")
            
        except Exception as e:
            raise Exception(f"Download failed: {str(e)}")
    
    @staticmethod
    def save_server_file(data, output_path, is_xz=True):
        """Save server file (handle both .xz and raw binary)"""
        try:
            with open(output_path, 'wb') as f:
                f.write(data)
            
            # If it's XZ file and we can extract it
            if is_xz and output_path.endswith('.xz'):
                try:
                    # Try to extract using Python's lzma
                    import lzma
                    with lzma.open(output_path) as f:
                        decompressed = f.read()
                    
                    # Remove .xz extension
                    final_path = output_path.replace('.xz', '')
                    with open(final_path, 'wb') as f:
                        f.write(decompressed)
                    
                    os.remove(output_path)
                    return final_path
                except ImportError:
                    print("lzma module not available, keeping .xz file")
                    return output_path
                except Exception as e:
                    print(f"XZ extraction failed: {e}, keeping original file")
                    return output_path
            else:
                return output_path
                
        except Exception as e:
            raise Exception(f"Save failed: {str(e)}")
    
    @staticmethod
    def install_on_device_windows(device_serial, server_path, install_path):
        """Push and install frida-server on device from Windows"""
        try:
            # On Windows, we don't use chmod on local file
            # Just push the file
            
            # Push to device
            if device_serial:
                cmd = f"adb -s {device_serial} push \"{server_path}\" \"{install_path}\""
            else:
                cmd = f"adb push \"{server_path}\" \"{install_path}\""
            
            print(f"Pushing with command: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Push failed: {result.stderr}")
            
            # Make executable on device (using ADB shell)
            if device_serial:
                cmd = f"adb -s {device_serial} shell chmod 755 \"{install_path}\""
            else:
                cmd = f"adb shell chmod 755 \"{install_path}\""
            
            print(f"Setting permissions: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                # Try alternative permission setting
                if device_serial:
                    cmd = f"adb -s {device_serial} shell \"chmod 755 {install_path}\""
                else:
                    cmd = f"adb shell \"chmod 755 {install_path}\""
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            return True
            
        except Exception as e:
            raise Exception(f"Installation failed: {str(e)}")
    
    @staticmethod
    def check_adb_connection(device_serial=None):
        """Check if ADB is working and device is connected"""
        try:
            if device_serial:
                cmd = f"adb -s {device_serial} devices"
            else:
                cmd = "adb devices"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if device_serial:
                # Check if specific device is in list
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip first line
                    if device_serial in line and "device" in line:
                        return True
                return False
            else:
                # Check if any device is connected
                lines = result.stdout.strip().split('\n')
                return len(lines) > 1
                
        except Exception as e:
            print(f"ADB check failed: {e}")
            return False

# ============================================================================
# MAIN APPLICATION
# ============================================================================

class FridaScriptRunner:
    def __init__(self, root):
        self.root = root
        self.root.title("🚀 Frida Automation Framework")
        self.root.geometry("1400x800")
        self.root.configure(bg=Config.COLORS['bg'])
        
        # Variables
        self.devices = []
        self.selected_device = None
        self.selected_script = None
        self.frida_process = None
        self.is_running = False
        self.device_rooted = False
        self.scripts = []
        self.device_arch = None
        self.os_type = platform.system()
        
        # Installer
        self.installer = FridaServerInstaller()
        
        # Initialize
        self.setup_gui()
        self.check_environment()
        
    def setup_gui(self):
        """Setup main GUI"""
        # Menu
        self.create_menu()
        
        # Main container
        main_container = ModernFrame(self.root)
        main_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header
        self.create_header(main_container)
        
        # Main content
        content_frame = ModernFrame(main_container)
        content_frame.pack(fill='both', expand=True, pady=(10, 0))
        
        # Three columns
        left_frame = ModernFrame(content_frame, width=350)
        left_frame.pack(side='left', fill='y', padx=(0, 5))
        left_frame.pack_propagate(False)
        self.create_device_panel(left_frame)
        
        middle_frame = ModernFrame(content_frame)
        middle_frame.pack(side='left', fill='both', expand=True, padx=5)
        self.create_scripts_panel(middle_frame)
        
        right_frame = ModernFrame(content_frame, width=400)
        right_frame.pack(side='right', fill='both', padx=(5, 0))
        right_frame.pack_propagate(False)
        self.create_execution_panel(right_frame)
        
        # Status bar
        self.create_status_bar(main_container)
        
    
    def create_menu(self):
        """Create menu bar"""
        menubar = Menu(self.root, bg=Config.COLORS['bg'], fg=Config.COLORS['fg'])
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0, bg=Config.COLORS['bg'], fg=Config.COLORS['fg'])
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Scan Scripts", command=self.scan_scripts)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Device menu
        device_menu = Menu(menubar, tearoff=0, bg=Config.COLORS['bg'], fg=Config.COLORS['fg'])
        menubar.add_cascade(label="Device", menu=device_menu)
        device_menu.add_command(label="Detect Devices", command=self.detect_devices)
        device_menu.add_command(label="Check Root", command=self.check_root)
        device_menu.add_command(label="Check Frida Server", command=self.check_frida_server_status)
        device_menu.add_separator()
        device_menu.add_command(label="ADB Shell", command=self.open_adb_shell)
        device_menu.add_command(label="ADB Reconnect", command=self.adb_reconnect)
        
        # Install menu
        install_menu = Menu(menubar, tearoff=0, bg=Config.COLORS['bg'], fg=Config.COLORS['fg'])
        menubar.add_cascade(label="Install", menu=install_menu)
        install_menu.add_command(label="Install Frida (PC)", command=self.install_frida_pc)
        install_menu.add_command(label="Install Frida Server (Device)", command=self.install_frida_server)
        install_menu.add_command(label="Auto Setup Device", command=self.auto_setup_device)
        install_menu.add_separator()
        install_menu.add_command(label="Manual Server Push", command=self.manual_server_push)
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0, bg=Config.COLORS['bg'], fg=Config.COLORS['fg'])
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Frida Console", command=self.open_frida_console)
        tools_menu.add_command(label="Open CodeShare Web", command=self.open_codeshare_web)

        
    def create_header(self, parent):
        """Create header"""
        header = ModernFrame(parent)
        header.pack(fill='x', pady=(0, 10))
        
        # Title with OS info
        os_info = f" ({self.os_type})"
        title = tk.Label(header, text=f"🚀 Frida Automation Framework {os_info}", 
                        bg=Config.COLORS['bg'], fg=Config.COLORS['fg'],
                        font=('Segoe UI', 18, 'bold'))
        title.pack(side='left')
        
        # Status
        self.status_label = tk.Label(header, text="Ready", 
                                    bg=Config.COLORS['bg'], fg=Config.COLORS['warning'],
                                    font=('Segoe UI', 10))
        self.status_label.pack(side='right')
    
    def create_device_panel(self, parent):
        """Create device panel with install button"""
        card = ModernFrame(parent, bg=Config.COLORS['card_bg'])
        card.pack(fill='both', expand=True)
        
        # Title
        title_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        title_frame.pack(fill='x', padx=10, pady=(10, 5))
        
        tk.Label(title_frame, text="📱 DEVICES", 
                bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                font=('Segoe UI', 12, 'bold')).pack(side='left')
        
        ModernButton(title_frame, "Refresh", self.detect_devices, 
                    width=8).pack(side='right')
        
        # Device list
        self.device_listbox = tk.Listbox(card, bg=Config.COLORS['card_bg'], 
                                        fg=Config.COLORS['fg'],
                                        selectbackground=Config.COLORS['accent'],
                                        selectforeground=Config.COLORS['fg'],
                                        font=('Consolas', 10),
                                        height=6)
        self.device_listbox.pack(fill='both', expand=True, padx=10, pady=5)
        self.device_listbox.bind('<<ListboxSelect>>', self.on_device_select)
        
        # Device info
        info_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        info_frame.pack(fill='x', padx=10, pady=5)
        
        self.device_info = scrolledtext.ScrolledText(info_frame, 
                                                    height=4,
                                                    bg=Config.COLORS['card_bg'],
                                                    fg=Config.COLORS['fg'],
                                                    font=('Consolas', 9))
        self.device_info.pack(fill='x')
        self.device_info.insert('1.0', 'No device selected')
        self.device_info.config(state='disabled')
        
        # Frida Server Status
        status_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.server_status_label = tk.Label(status_frame, 
                                           text="Frida Server: ❓ Not Checked",
                                           bg=Config.COLORS['card_bg'], 
                                           fg=Config.COLORS['warning'],
                                           font=('Segoe UI', 10))
        self.server_status_label.pack(anchor='w')
        
        # Install section
        install_card = ModernFrame(card, bg=Config.COLORS['install_bg'])
        install_card.pack(fill='x', padx=10, pady=10)
        
        tk.Label(install_card, text="🔧 FRIDA SERVER INSTALL", 
                bg=Config.COLORS['install_bg'], fg=Config.COLORS['fg'],
                font=('Segoe UI', 11, 'bold')).pack(anchor='w', pady=(5, 0))
        
        # Architecture info
        arch_frame = ModernFrame(install_card, bg=Config.COLORS['install_bg'])
        arch_frame.pack(fill='x', padx=5, pady=2)
        
        self.arch_label = tk.Label(arch_frame, 
                                  text="Architecture: Unknown",
                                  bg=Config.COLORS['install_bg'], 
                                  fg=Config.COLORS['fg'])
        self.arch_label.pack(anchor='w')
        
        # Install path selection
        path_frame = ModernFrame(install_card, bg=Config.COLORS['install_bg'])
        path_frame.pack(fill='x', padx=5, pady=2)
        
        tk.Label(path_frame, text="Install Path:", 
                bg=Config.COLORS['install_bg'], fg=Config.COLORS['fg']).pack(side='left')
        
        self.path_var = tk.StringVar(value=Config.SELECTED_SERVER_PATH)
        path_combo = ttk.Combobox(path_frame, textvariable=self.path_var,
                                 values=Config.FRIDA_SERVER_PATHS,
                                 width=30, state='readonly')
        path_combo.pack(side='left', padx=5)
        
        # Install buttons
        btn_frame = ModernFrame(install_card, bg=Config.COLORS['install_bg'])
        btn_frame.pack(fill='x', padx=5, pady=5)
        
        ModernButton(btn_frame, "Check", self.check_frida_server_status,
                    bg='#2196F3', width=8).pack(side='left', padx=2)
        ModernButton(btn_frame, "Install", self.install_frida_server,
                    bg='#4CAF50', width=8).pack(side='left', padx=2)
        ModernButton(btn_frame, "Start", self.start_frida_server,
                    bg='#FF9800', width=8).pack(side='left', padx=2)
        ModernButton(btn_frame, "Stop", self.stop_frida_server,
                    bg='#f44336', width=8).pack(side='left', padx=2)
    
    def create_scripts_panel(self, parent):
        """Create scripts panel"""
        card = ModernFrame(parent, bg=Config.COLORS['card_bg'])
        card.pack(fill='both', expand=True)
        
        # Title
        title_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        title_frame.pack(fill='x', padx=10, pady=(10, 5))
        
        tk.Label(title_frame, text="📜 SCRIPTS", 
                bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                font=('Segoe UI', 12, 'bold')).pack(side='left')
        
        # Controls
        ctrl_frame = ModernFrame(title_frame, bg=Config.COLORS['card_bg'])
        ctrl_frame.pack(side='right')
        
        ModernButton(ctrl_frame, "Scan", self.scan_scripts, 
                    width=8).pack(side='left', padx=2)
        ModernButton(ctrl_frame, "Open Folder", self.open_script_folder, 
                    width=10).pack(side='left', padx=2)
        
        # Search
        search_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        search_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(search_frame, text="Search:", 
                bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg']).pack(side='left')
        
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                               bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                               insertbackground=Config.COLORS['fg'], width=40)
        search_entry.pack(side='left', padx=5)
        search_entry.bind('<KeyRelease>', self.filter_scripts)
        
        # Script list
        list_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.script_listbox = tk.Listbox(list_frame, 
                                        bg=Config.COLORS['card_bg'],
                                        fg=Config.COLORS['fg'],
                                        selectbackground=Config.COLORS['accent'],
                                        selectforeground=Config.COLORS['fg'],
                                        font=('Consolas', 10))
        self.script_listbox.pack(side='left', fill='both', expand=True)
        self.script_listbox.bind('<<ListboxSelect>>', self.on_script_select)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side='right', fill='y')
        self.script_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.script_listbox.yview)
        
        # CodeShare section
        codeshare_frame = ModernFrame(card, bg=Config.COLORS['codeshare_bg'])
        codeshare_frame.pack(fill='both', expand=True, padx=10, pady=(10, 5))
        
        tk.Label(codeshare_frame, text="🌐 CODESHARE", 
                bg=Config.COLORS['codeshare_bg'], fg=Config.COLORS['fg'],
                font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(0, 5))
        
        # CodeShare input
        cs_input_frame = ModernFrame(codeshare_frame, bg=Config.COLORS['codeshare_bg'])
        cs_input_frame.pack(fill='x', pady=2)
        
        tk.Label(cs_input_frame, text="Author/Script:", 
                bg=Config.COLORS['codeshare_bg'], fg=Config.COLORS['fg']).pack(side='left')
        
        self.codeshare_var = tk.StringVar()
        cs_entry = tk.Entry(cs_input_frame, textvariable=self.codeshare_var,
                           bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                           insertbackground=Config.COLORS['fg'], width=40)
        cs_entry.pack(side='left', padx=5)
        cs_entry.insert(0, "")
        
        ModernButton(cs_input_frame, "Use", self.use_codeshare,
                    bg='#4CAF50', width=8).pack(side='left', padx=2)
    
    def create_execution_panel(self, parent):
        """Create execution panel"""
        card = ModernFrame(parent, bg=Config.COLORS['card_bg'])
        card.pack(fill='both', expand=True)
        
        # Title
        title_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        title_frame.pack(fill='x', padx=10, pady=(10, 5))
        
        tk.Label(title_frame, text="⚡ EXECUTION", 
                bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                font=('Segoe UI', 12, 'bold')).pack(side='left')
        
        # Source selection
        source_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        source_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(source_frame, text="Script Source:", 
                bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                font=('Segoe UI', 10, 'bold')).pack(anchor='w')
        
        self.source_var = tk.StringVar(value="local")
        
        tk.Radiobutton(source_frame, text="📁 Local File", 
                      variable=self.source_var, value="local",
                      bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                      selectcolor=Config.COLORS['card_bg'],
                      command=self.update_execution_ui).pack(anchor='w', pady=2)
        
        tk.Radiobutton(source_frame, text="🌐 CodeShare", 
                      variable=self.source_var, value="codeshare",
                      bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                      selectcolor=Config.COLORS['card_bg'],
                      command=self.update_execution_ui).pack(anchor='w', pady=2)
        
        # App selection
        app_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        app_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(app_frame, text="Target App:", 
                bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                font=('Segoe UI', 10, 'bold')).pack(anchor='w')
        
        self.app_var = tk.StringVar()
        self.app_combo = ttk.Combobox(app_frame, textvariable=self.app_var,
                                     state='readonly', width=35)
        self.app_combo.pack(fill='x', pady=2)
        
        ModernButton(app_frame, "List Apps", self.list_apps, 
                    width=10).pack(anchor='e', pady=2)
        
        # Mode selection
        mode_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        mode_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(mode_frame, text="Execution Mode:", 
                bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                font=('Segoe UI', 10, 'bold')).pack(anchor='w')
        
        self.mode_var = tk.StringVar(value="attach")
        
        tk.Radiobutton(mode_frame, text="🔗 Attach (Running App)", 
                      variable=self.mode_var, value="attach",
                      bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                      selectcolor=Config.COLORS['card_bg']).pack(anchor='w', pady=2)
        
        tk.Radiobutton(mode_frame, text="🚀 Spawn (Launch Fresh)", 
                      variable=self.mode_var, value="spawn",
                      bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                      selectcolor=Config.COLORS['card_bg']).pack(anchor='w', pady=2)
        
        # Execute button
        exec_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        exec_frame.pack(fill='x', padx=10, pady=10)
        
        self.execute_btn = ModernButton(exec_frame, "⚡ EXECUTE SCRIPT", 
                                       self.execute_script)
        self.execute_btn.pack(fill='x', pady=10)
        
        # Output
        output_frame = ModernFrame(card, bg=Config.COLORS['card_bg'])
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        tk.Label(output_frame, text="Execution Output:", 
                bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'],
                font=('Segoe UI', 10, 'bold')).pack(anchor='w')
        
        # Output controls
        output_ctrl = ModernFrame(output_frame, bg=Config.COLORS['card_bg'])
        output_ctrl.pack(fill='x', pady=2)
        
        ModernButton(output_ctrl, "Clear", self.clear_output, 
                    width=8).pack(side='left', padx=2)
        ModernButton(output_ctrl, "Stop", self.stop_execution, 
                    width=8).pack(side='left', padx=2)
        ModernButton(output_ctrl, "Save", self.save_output, 
                    width=8).pack(side='right', padx=2)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(output_frame,
                                                    height=20,
                                                    bg=Config.COLORS['terminal_bg'],
                                                    fg=Config.COLORS['terminal_fg'],
                                                    font=('Consolas', 10))
        self.output_text.pack(fill='both', expand=True)
    
    def create_status_bar(self, parent):
        """Create status bar"""
        status = ModernFrame(parent, bg=Config.COLORS['card_bg'], height=30)
        status.pack(fill='x', pady=(10, 0))
        status.pack_propagate(False)
        
        # Stats
        stats_frame = ModernFrame(status, bg=Config.COLORS['card_bg'])
        stats_frame.pack(side='left', padx=10)
        
        self.device_stat = tk.Label(stats_frame, text="Devices: 0", 
                                   bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'])
        self.device_stat.pack(side='left', padx=5)
        
        self.script_stat = tk.Label(stats_frame, text="Scripts: 0", 
                                   bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'])
        self.script_stat.pack(side='left', padx=5)
        
        # Developer name 
        center_frame = ModernFrame(stats_frame, bg=Config.COLORS['card_bg'])
        center_frame.pack(side='right', expand=True, fill='both')
    
        dev_label = tk.Label(center_frame, text="                                                                                    Developed by: Ali Raza", 
                        bg=Config.COLORS['card_bg'], fg=Config.COLORS['accent'],
                        font=('Segoe UI', 15, 'bold'))
        dev_label.pack(expand=True)  # Center alignment
        
        # OS info
        self.os_label = tk.Label(stats_frame, text=f"OS: {self.os_type}", 
                                bg=Config.COLORS['card_bg'], fg=Config.COLORS['fg'])
        self.os_label.pack(side='left', padx=5)
        
        # Progress
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(status, variable=self.progress_var,
                                       length=200, mode='determinate')
        self.progress.pack(side='right', padx=10)
    
    # ============================================================================
    # WINDOWS SPECIFIC FUNCTIONS
    # ============================================================================
    
    def check_frida_server_status(self):
        """Check if frida-server is installed and running - Windows compatible"""
        if not self.selected_device:
            messagebox.showwarning("Warning", "Select a device first")
            return
        
        self.log("Checking frida-server status...")
        
        def check():
            try:
                install_path = self.path_var.get()
                
                # Check if server binary exists
                cmd = f"adb -s {self.selected_device} shell ls -la \"{install_path}\""
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if "No such file" in result.stdout or "not found" in result.stdout:
                    self.root.after(0, self.update_server_status, 
                                   "❌ Not Installed", Config.COLORS['error'])
                    self.log(f"Frida server not found at {install_path}", "warning")
                    return False
                else:
                    # Check if running
                    cmd = f"adb -s {self.selected_device} shell ps -A | grep frida-server"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if "frida-server" in result.stdout:
                        self.root.after(0, self.update_server_status, 
                                       "✅ Installed & Running", Config.COLORS['success'])
                        self.log("Frida server is installed and running", "success")
                        return True
                    #else:
                        #self.root.after(0, self.update_server_status, 
                         #              "⚠ Installed but not running", Config.COLORS['warning'])
                        #self.log("Frida server installed but not running", "warning")
                        #return True
                        
            except Exception as e:
                self.root.after(0, self.update_server_status, 
                               "❓ Check Failed", Config.COLORS['error'])
                self.log(f"Status check failed: {str(e)}", "error")
                return False
        
        threading.Thread(target=check, daemon=True).start()
    
    def install_frida_server(self):
        """Automatically install frida-server on device - Windows compatible"""
        if not self.selected_device:
            messagebox.showwarning("Warning", "Select a device first")
            return
        
        # Check ADB connection first
        if not self.installer.check_adb_connection(self.selected_device):
            messagebox.showerror("ADB Error", 
                               "Device not connected or ADB not working.\n"
                               "Check:\n"
                               "1. USB Debugging is enabled\n"
                               "2. USB cable is connected\n"
                               "3. Run 'ADB Reconnect' from Device menu")
            return
        
        self.log("Starting frida-server installation...")
        
        def install():
            try:
                # Update progress
                self.root.after(0, self.progress_var.set, 10)
                
                # Step 1: Get device architecture
                self.log("Detecting device architecture...")
                self.device_arch = self.installer.get_device_architecture(self.selected_device)
                self.root.after(0, self.arch_label.config, 
                              {"text": f"Architecture: {self.device_arch}"})
                
                self.log(f"Device architecture: {self.device_arch}")
                
                # Step 2: Get frida version
                self.log("Getting frida version...")
                frida_version = self.installer.get_frida_version()
                if not frida_version:
                    frida_version = self.installer.get_latest_frida_release()
                    self.log(f"Using latest version: {frida_version}", "warning")
                else:
                    self.log(f"PC Frida version: {frida_version}")
                
                # Step 3: Download frida-server
                self.log(f"Downloading frida-server {frida_version} for {self.device_arch}...")
                self.root.after(0, self.progress_var.set, 30)
                
                try:
                    xz_data = self.installer.download_frida_server(frida_version, self.device_arch)
                    is_xz = True
                except Exception as download_error:
                    self.log(f"XZ download failed: {download_error}", "warning")
                    
                    # Try downloading raw binary
                    try:
                        raw_url = f"https://github.com/frida/frida/releases/download/{frida_version}/frida-server-{frida_version}-android-{self.device_arch}"
                        response = requests.get(raw_url, timeout=30)
                        if response.status_code == 200:
                            xz_data = response.content
                            is_xz = False
                            self.log("Downloaded raw binary (not compressed)", "success")
                        else:
                            raise Exception("Both XZ and raw download failed")
                    except:
                        raise Exception(f"Download failed: {download_error}")
                
                # Step 4: Save file
                self.log("Saving frida-server...")
                self.root.after(0, self.progress_var.set, 60)
                
                temp_dir = tempfile.gettempdir()
                if is_xz:
                    temp_file = os.path.join(temp_dir, f"frida-server-{frida_version}-android-{self.device_arch}.xz")
                else:
                    temp_file = os.path.join(temp_dir, f"frida-server-{frida_version}-android-{self.device_arch}")
                
                server_path = self.installer.save_server_file(xz_data, temp_file, is_xz)
                
                # Step 5: Install on device
                self.log("Installing on device...")
                self.root.after(0, self.progress_var.set, 80)
                
                install_path = self.path_var.get()
                success = self.installer.install_on_device_windows(
                    self.selected_device, 
                    server_path, 
                    install_path
                )
                
                if success:
                    self.log(f"Frida server installed successfully at {install_path}!", "success")
                    self.root.after(0, self.update_server_status, 
                                   "✅ Installed", Config.COLORS['success'])
                    
                    # Ask to start server
                    response = messagebox.askyesno("Success", 
                                                 f"Frida server installed at:\n{install_path}\n\n"
                                                 "Start frida-server now?")
                    if response:
                        self.start_frida_server()
                else:
                    self.log("Installation failed", "error")
                
                # Cleanup
                try:
                    if os.path.exists(server_path):
                        os.remove(server_path)
                except:
                    pass
                
                self.root.after(0, self.progress_var.set, 100)
                time.sleep(1)
                self.root.after(0, self.progress_var.set, 0)
                
            except Exception as e:
                self.log(f"Installation failed: {str(e)}", "error")
                messagebox.showerror("Installation Failed", 
                                   f"Error: {str(e)}\n\n"
                                   "You can manually:\n"
                                   "1. Download frida-server from GitHub\n"
                                   "2. Push to device using: adb push frida-server /data/local/tmp/\n"
                                   "3. Set permissions: adb shell chmod 755 /data/local/tmp/frida-server")
                self.root.after(0, self.progress_var.set, 0)
        
        threading.Thread(target=install, daemon=True).start()
    
    def manual_server_push(self):
        """Manual frida-server push option"""
        if not self.selected_device:
            messagebox.showwarning("Warning", "Select a device first")
            return
        
        # Ask for local file
        file_path = filedialog.askopenfilename(
            title="Select frida-server binary",
            filetypes=[("Binary files", "*.xz;*"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        # Ask for install path
        install_path = self.path_var.get()
        
        response = messagebox.askyesno("Confirm", 
                                     f"Push file:\n{file_path}\n\n"
                                     f"To device path:\n{install_path}\n\n"
                                     "Continue?")
        if not response:
            return
        
        self.log(f"Manually pushing frida-server to {install_path}...")
        
        def push():
            try:
                # Push file
                cmd = f"adb -s {self.selected_device} push \"{file_path}\" \"{install_path}\""
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode != 0:
                    raise Exception(f"Push failed: {result.stderr}")
                
                # Set permissions
                cmd = f"adb -s {self.selected_device} shell chmod 755 \"{install_path}\""
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log(f"Manual push successful to {install_path}", "success")
                    self.check_frida_server_status()
                else:
                    self.log(f"Push successful but permission setting failed", "warning")
                    
            except Exception as e:
                self.log(f"Manual push failed: {str(e)}", "error")
        
        threading.Thread(target=push, daemon=True).start()
    
    def adb_reconnect(self):
        """Restart ADB server"""
        self.log("Restarting ADB server...")
        
        def reconnect():
            try:
                # Kill server
                subprocess.run("adb kill-server", shell=True, capture_output=True)
                time.sleep(1)
                
                # Start server
                subprocess.run("adb start-server", shell=True, capture_output=True)
                time.sleep(2)
                
                # Check devices
                result = subprocess.run("adb devices", shell=True, capture_output=True, text=True)
                
                self.log("ADB restarted", "success")
                
                # Update device list
                lines = result.stdout.strip().split('\n')[1:]
                devices = []
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            serial = parts[0]
                            status = parts[1]
                            devices.append(f"{serial} ({status})")
                
                self.root.after(0, self.update_device_list, devices)
                
            except Exception as e:
                self.log(f"ADB restart failed: {str(e)}", "error")
        
        threading.Thread(target=reconnect, daemon=True).start()
    
    def update_server_status(self, status, color):
        """Update server status label"""
        self.server_status_label.config(text=f"Frida Server: {status}", fg=color)
    
    # ============================================================================
    # CORE FUNCTIONS (Windows compatible)
    # ============================================================================
    
    def log(self, message, level="info"):
        """Log message to output"""
        timestamp = time.strftime("%H:%M:%S")
        
        colors = {
            "info": Config.COLORS['fg'],
            "success": Config.COLORS['success'],
            "warning": Config.COLORS['warning'],
            "error": Config.COLORS['error']
        }
        
        color = colors.get(level, Config.COLORS['fg'])
        
        # Update status
        self.status_label.config(text=message, fg=color)
        
        # Add to output
        self.output_text.insert('end', f"[{timestamp}] {message}\n")
        self.output_text.see('end')
        
        print(f"[{timestamp}] {message}")
    
    def run_command(self, cmd, check=True, timeout=30):
        """Run shell command - Windows compatible"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, 
                                  text=True, timeout=timeout)
            if check and result.returncode != 0:
                raise Exception(f"Command failed: {result.stderr}")
            return result
        except subprocess.TimeoutExpired:
            raise Exception("Command timed out")
        except Exception as e:
            raise Exception(f"Command error: {str(e)}")
    
    def adb_command(self, cmd, check=True):
        """Run ADB command with device"""
        if self.selected_device:
            full_cmd = f"adb -s {self.selected_device} {cmd}"
        else:
            full_cmd = f"adb {cmd}"
        return self.run_command(full_cmd, check)
    
    def check_environment(self):
        """Check if required tools are installed"""
        self.log("Checking environment...")
        
        def check():
            try:
                # Check Python
                version = sys.version_info
                if version.major < 3 or (version.major == 3 and version.minor < 7):
                    self.log("Python 3.7+ required", "error")
                    return
                
                # Check ADB
                try:
                    result = self.run_command("adb --version", check=False)
                    if result.returncode == 0:
                        self.log(f"ADB: {result.stdout.splitlines()[0]}", "success")
                    else:
                        self.log("ADB found but error in version check", "warning")
                except:
                    self.log("ADB not found. Install Android SDK Platform Tools", "error")
                
                # Check Frida
                try:
                    result = self.run_command("frida --version")
                    self.log(f"Frida: v{result.stdout.strip()}", "success")
                except:
                    self.log("Frida not installed. Use Install > Install Frida (PC)", "warning")
                
                # Auto-detect devices
                self.detect_devices()
                
            except Exception as e:
                self.log(f"Environment check failed: {str(e)}", "error")
        
        threading.Thread(target=check, daemon=True).start()
    
    def detect_devices(self):
        """Detect connected devices"""
        self.log("Detecting devices...")
        
        def detect():
            try:
                result = self.run_command("adb devices")
                lines = result.stdout.strip().split('\n')[1:]
                
                devices = []
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            serial = parts[0]
                            status = parts[1]
                            devices.append(f"{serial} ({status})")
                
                self.root.after(0, self.update_device_list, devices)
                
                if devices:
                    self.log(f"Found {len(devices)} device(s)", "success")
                else:
                    self.log("No devices found", "warning")
                    
            except Exception as e:
                self.log(f"Device detection failed: {str(e)}", "error")
        
        threading.Thread(target=detect, daemon=True).start()
    
    def update_device_list(self, devices):
        """Update device listbox"""
        self.device_listbox.delete(0, 'end')
        for device in devices:
            self.device_listbox.insert('end', device)
        
        self.device_stat.config(text=f"Devices: {len(devices)}")
        self.devices = devices
        
        # Auto-select first device
        if devices:
            self.device_listbox.selection_set(0)
            self.on_device_select(None)
    
    def on_device_select(self, event):
        """Handle device selection"""
        selection = self.device_listbox.curselection()
        if selection:
            device_str = self.device_listbox.get(selection[0])
            self.selected_device = device_str.split()[0]
            self.log(f"Selected device: {self.selected_device}", "success")
            self.get_device_info()
            self.check_root()
            self.check_frida_server_status()
            self.list_apps()
            
            # Get architecture
            def get_arch():
                arch = self.installer.get_device_architecture(self.selected_device)
                self.root.after(0, self.arch_label.config, 
                              {"text": f"Architecture: {arch}"})
            
            threading.Thread(target=get_arch, daemon=True).start()
    
    def get_device_info(self):
        """Get device information"""
        if not self.selected_device:
            return
        
        def get_info():
            try:
                info = "=== Device Information ===\n\n"
                
                # Get basic info
                props = {
                    "Model": "ro.product.model",
                    "Brand": "ro.product.brand",
                    "Device": "ro.product.device",
                    "Android Version": "ro.build.version.release",
                    "SDK Version": "ro.build.version.sdk",
                    "Architecture": "ro.product.cpu.abi"
                }
                
                for name, prop in props.items():
                    try:
                        result = self.adb_command(f"shell getprop {prop}")
                        value = result.stdout.strip() or "Unknown"
                        info += f"{name}: {value}\n"
                    except:
                        info += f"{name}: Unknown\n"
                
                # Get serial
                info += f"\nSerial: {self.selected_device}\n"
                
                # Update GUI
                self.root.after(0, self.update_device_info, info)
                
            except Exception as e:
                self.log(f"Failed to get device info: {str(e)}", "error")
        
        threading.Thread(target=get_info, daemon=True).start()
    
    def update_device_info(self, info):
        """Update device info display"""
        self.device_info.config(state='normal')
        self.device_info.delete('1.0', 'end')
        self.device_info.insert('1.0', info)
        self.device_info.config(state='disabled')
    
    def check_root(self):
        """Check if device is rooted"""
        if not self.selected_device:
            return
        
        def check():
            try:
                # Check for su binary
                result = self.adb_command("shell which su", check=False)
                if result.returncode == 0 and result.stdout.strip():
                    self.device_rooted = True
                    self.log("Device is rooted", "success")
                else:
                    self.device_rooted = False
                    self.log("Device is not rooted (spawn mode may fail)", "warning")
                    
            except Exception as e:
                self.device_rooted = False
                self.log(f"Root check failed: {str(e)}", "error")
        
        threading.Thread(target=check, daemon=True).start()
    
    def start_frida_server(self):
        """Start Frida server on device - Windows compatible"""
        if not self.selected_device:
            self.log("Select a device first", "error")
            return
        
        self.log("Starting Frida server...")
        
        def start():
            try:
                install_path = self.path_var.get()
                
                # Check if server binary exists
                cmd = f"adb -s {self.selected_device} shell ls -la \"{install_path}\""
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if "No such file" in result.stdout or "not found" in result.stdout:
                    response = messagebox.askyesno("Frida Server Not Found", 
                                                 f"Frida server not found at:\n{install_path}\n\n"
                                                 "Install automatically now?")
                    if response:
                        self.install_frida_server()
                    return
                
                # Kill existing server
                self.adb_command("shell pkill -9 -f frida-server", check=False)
                time.sleep(1)
                
                # Start server based on root status
                if self.device_rooted:
                    self.log("Starting with root privileges...", "info")
                    cmd = f"adb -s {self.selected_device} shell su root  \"{install_path} \" &"
                else:
                    self.log("Starting without root...", "info")
                    cmd = f"adb -s {self.selected_device} shell \"{install_path} -D\" &"
                
                subprocess.run(cmd, shell=True, check=False)
                
                time.sleep(3)
                
                # Verify
                self.check_frida_server_status()
                    
            except Exception as e:
                self.log(f"Failed to start Frida server: {str(e)}", "error")
        
        threading.Thread(target=start, daemon=True).start()
    
    def stop_frida_server(self):
        """Stop Frida server"""
        if not self.selected_device:
            return
        
        def stop():
            try:
                self.adb_command("shell pkill -9 -f frida-server", check=False)
                self.log("Frida server stopped", "success")
                self.update_server_status("🛑 Stopped", Config.COLORS['warning'])
            except Exception as e:
                self.log(f"Failed to stop Frida server: {str(e)}", "error")
        
        threading.Thread(target=stop, daemon=True).start()
    
    def auto_setup_device(self):
        """Auto setup device - check and install if needed"""
        if not self.selected_device:
            messagebox.showwarning("Warning", "Select a device first")
            return
        
        self.log("Starting auto setup...")
        
        def setup():
            try:
                # First check connection
                if not self.installer.check_adb_connection(self.selected_device):
                    messagebox.showerror("Connection Error", 
                                       "Device not connected.\n"
                                       "Check USB connection and USB debugging.")
                    return
                
                # Check current status
                install_path = self.path_var.get()
                cmd = f"adb -s {self.selected_device} shell ls -la \"{install_path}\""
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if "No such file" in result.stdout or "not found" in result.stdout:
                    # Not installed
                    response = messagebox.askyesno("Auto Setup", 
                                                 "Frida server not found on device.\n\n"
                                                 "Do you want to automatically:\n"
                                                 "1. Detect architecture\n"
                                                 "2. Download matching frida-server\n"
                                                 "3. Install on device\n"
                                                 "4. Start server")
                    if response:
                        self.install_frida_server()
                else:
                    # Installed, check if running
                    cmd = f"adb -s {self.selected_device} shell ps -A | grep frida-server"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if "frida-server" not in result.stdout:
                        response = messagebox.askyesno("Auto Setup", 
                                                     "Frida server installed but not running.\n\n"
                                                     "Start frida-server now?")
                        if response:
                            self.start_frida_server()
                    else:
                        self.log("Frida server already installed and running", "success")
                        
            except Exception as e:
                self.log(f"Auto setup failed: {str(e)}", "error")
        
        threading.Thread(target=setup, daemon=True).start()
    
    def scan_scripts(self):
        """Scan for Frida scripts"""
        self.log("Scanning for scripts...")
        
        def scan():
            try:
                scripts = []
                
                for script_dir in Config.SCRIPT_DIRS:
                    script_path = Path(script_dir)
                    if script_path.exists():
                        for js_file in script_path.rglob('*.js'):
                            scripts.append(str(js_file))
                
                self.root.after(0, self.update_script_list, scripts)
                
                if scripts:
                    self.log(f"Found {len(scripts)} scripts", "success")
                else:
                    self.log("No scripts found. Create a 'scripts' folder.", "warning")
                    self.create_sample_scripts()
                    
            except Exception as e:
                self.log(f"Script scan failed: {str(e)}", "error")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def create_sample_scripts(self):
        """Create sample scripts"""
        script_dir = Path("scripts")
        script_dir.mkdir(exist_ok=True)
        
        samples = {
            "ssl_bypass.js": """
Java.perform(function() {
    console.log("[+] SSL Pinning Bypass Loaded");
    
    // Bypass certificate pinning
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
        console.log("[+] Certificate pinning bypassed");
    };
});
""",
            "root_detection.js": """
Java.perform(function() {
    console.log("[+] Root Detection Bypass Loaded");
    
    // Bypass root detection
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() {
        console.log("[+] Root detection bypassed");
        return false;
    };
});
"""
        }
        
        for filename, content in samples.items():
            filepath = script_dir / filename
            if not filepath.exists():
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        self.log("Created sample scripts in 'scripts' folder", "success")
    
    def update_script_list(self, scripts):
        """Update script listbox"""
        self.script_listbox.delete(0, 'end')
        for script in sorted(scripts):
            self.script_listbox.insert('end', os.path.basename(script))
        
        self.script_stat.config(text=f"Scripts: {len(scripts)}")
        self.scripts = scripts
    
    def filter_scripts(self, event=None):
        """Filter scripts based on search"""
        search = self.search_var.get().lower()
        
        # If no search, show all
        if not search:
            self.update_script_list(self.scripts)
            return
        
        # Filter scripts
        filtered = [s for s in self.scripts if search in os.path.basename(s).lower()]
        self.script_listbox.delete(0, 'end')
        for script in filtered:
            self.script_listbox.insert('end', os.path.basename(script))
    
    def on_script_select(self, event):
        """Handle script selection"""
        selection = self.script_listbox.curselection()
        if selection:
            index = selection[0]
            self.selected_script = self.scripts[index]
            self.log(f"Selected script: {os.path.basename(self.selected_script)}", "success")
    
    def use_codeshare(self):
        """Use CodeShare script"""
        codeshare_path = self.codeshare_var.get().strip()
        if not codeshare_path:
            messagebox.showwarning("Warning", "Enter author/script path")
            return
        
        # Update UI to show CodeShare is selected
        self.source_var.set("codeshare")
        self.update_execution_ui()
        
        self.log(f"CodeShare script selected: {codeshare_path}", "success")
    
    def update_execution_ui(self):
        """Update execution UI based on source"""
        source = self.source_var.get()
        if source == "codeshare":
            self.execute_btn.config(text="⚡ EXECUTE CODESHARE SCRIPT")
        else:
            self.execute_btn.config(text="⚡ EXECUTE LOCAL SCRIPT")
    
    def list_apps(self):
        """List installed applications"""
        if not self.selected_device:
            self.log("Select a device first", "error")
            return
        
        self.log("Listing applications...")
        
        def list():
            try:
                apps = []
                
                # Try with frida-ps
                try:
                    result = self.run_command("frida-ps -Uai", timeout=15, check=False)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        for line in lines:
                            if '----' in line:
                                continue
                            if line.strip():
                                parts = line.split()
                                if len(parts) >= 3:
                                    pid = parts[0]
                                    package = parts[-1]
                                    if pid != '-':
                                        apps.append(f"{package} (PID: {pid})")
                                    else:
                                        apps.append(f"{package}")
                except:
                    pass
                
                self.root.after(0, self.update_app_list, apps)
                
                if apps:
                    self.log(f"Found {len(apps)} applications", "success")
                else:
                    self.log("No applications found. Start Frida server first.", "warning")
                    
            except Exception as e:
                self.log(f"Failed to list apps: {str(e)}", "error")
        
        threading.Thread(target=list, daemon=True).start()
    
    def update_app_list(self, apps):
        """Update app combobox"""
        self.app_combo['values'] = apps
        if apps:
            self.app_var.set(apps[0])
    
    def get_app_pid(self, package_name):
        """Get PID of running app"""
        try:
            result = self.adb_command(f"shell pidof {package_name}", check=False)
            if result.stdout.strip():
                return result.stdout.strip().split()[0]
            return None
        except:
            return None
    
    def execute_script(self):
        """Execute script - supports both local and CodeShare"""
        # Validation
        if not self.selected_device:
            messagebox.showerror("Error", "Please select a device first")
            return
        
        if not self.app_var.get():
            messagebox.showerror("Error", "Please select an application")
            return
        
        # Get package name
        app_str = self.app_var.get()
        package_match = re.match(r'([\w\.]+)', app_str)
        if not package_match:
            messagebox.showerror("Error", "Invalid application format")
            return
        
        package_name = package_match.group(1)
        mode = self.mode_var.get()
        source = self.source_var.get()
        
        # Prepare command based on source
        cmd_parts = ["frida", "-U"]
        
        if source == "local":
            if not self.selected_script:
                messagebox.showerror("Error", "Please select a script first")
                return
            
            script_path = os.path.abspath(self.selected_script)
            cmd_parts.extend(["-l", script_path])
            
            self.log(f"Executing local script: {os.path.basename(script_path)}")
            
        else:  # CODESHARE
            if not self.codeshare_var.get().strip():
                messagebox.showerror("Error", "Enter CodeShare author/script path")
                return
            
            codeshare_path = self.codeshare_var.get().strip()
            cmd_parts.extend(["--codeshare", codeshare_path])
            
            self.log(f"Executing CodeShare script: {codeshare_path}")
        
        # Add target based on mode
        if mode == "attach":
            pid_match = re.search(r'PID:\s*(\d+)', app_str)
            if pid_match:
                pid = pid_match.group(1)
                cmd_parts.extend(["-p", pid])
            else:
                pid = self.get_app_pid(package_name)
                if pid:
                    cmd_parts.extend(["-p", pid])
                else:
                    response = messagebox.askyesno("App Not Running", 
                                                 f"App '{package_name}' is not running.\n\n"
                                                 f"Start app and attach?")
                    if response:
                        self.adb_command(f"shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1", 
                                       check=False)
                        time.sleep(3)
                        pid = self.get_app_pid(package_name)
                        if pid:
                            cmd_parts.extend(["-p", pid])
                        else:
                            messagebox.showerror("Error", "Failed to start application")
                            return
                    else:
                        return
        else:  # SPAWN MODE
            if not self.device_rooted:
                response = messagebox.askyesno("Warning", 
                                             "Device is not rooted.\n"
                                             "Spawn mode requires root access.\n\n"
                                             "Try anyway?")
                if not response:
                    return
            
            # Kill app if running
            pid = self.get_app_pid(package_name)
            if pid:
                self.adb_command(f"shell am force-stop {package_name}", check=False)
                time.sleep(1)
            
            cmd_parts.extend(["-f", package_name])
        
        # Build final command
        cmd = " ".join(cmd_parts)
        
        # Log command
        self.log(f"Mode: {mode.upper()} | Target: {package_name}")
        self.log(f"Command: {cmd}")
        
        # Clear output
        self.output_text.delete('1.0', 'end')
        
        # Disable execute button
        self.execute_btn.config(state='disabled', text="⏳ Running...")
        self.is_running = True
        
        # Execute in thread
        def execute():
            try:
                self.frida_process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                def read_output():
                    while True:
                        line = self.frida_process.stdout.readline()
                        if not line:
                            break
                        if line.strip():
                            self.root.after(0, self.append_output, line)
                
                def read_errors():
                    while True:
                        line = self.frida_process.stderr.readline()
                        if not line:
                            break
                        if line.strip():
                            self.root.after(0, self.append_output, f"[ERROR] {line}")
                
                output_thread = threading.Thread(target=read_output, daemon=True)
                error_thread = threading.Thread(target=read_errors, daemon=True)
                
                output_thread.start()
                error_thread.start()
                
                return_code = self.frida_process.wait()
                
                output_thread.join(timeout=2)
                error_thread.join(timeout=2)
                
                if return_code == 0:
                    self.root.after(0, self.execution_complete, "✅ Script execution completed")
                elif return_code == 1:
                    self.root.after(0, self.execution_complete, "⚠ Script exited with warnings")
                else:
                    self.root.after(0, self.execution_complete, f"❌ Script exited with code {return_code}")
                    
            except Exception as e:
                error_msg = str(e)
                
                if "need Gadget" in error_msg or "jailed" in error_msg:
                    error_msg = ("Device is not rooted. Spawn mode requires root access.\n"
                               "Use Attach mode instead, or root your device.")
                elif "unable to find process" in error_msg:
                    error_msg = ("Process not found.\n"
                               "For Attach mode: Make sure app is running.\n"
                               "For Spawn mode: Check package name.")
                elif "timed out" in error_msg:
                    error_msg = ("Connection timed out.\n"
                               "1. Check if Frida server is running\n"
                               "2. Check USB connection\n"
                               "3. Restart ADB: adb kill-server && adb start-server")
                elif "Device not found" in error_msg:
                    error_msg = ("Device not found.\n"
                               "1. Reconnect USB cable\n"
                               "2. Check USB debugging is enabled\n"
                               "3. Run: adb devices")
                elif "codeshare" in error_msg.lower():
                    error_msg = ("CodeShare error.\n"
                               "1. Check internet connection\n"
                               "2. Verify script path format: author/script-name\n"
                               "3. Try: pcipolloni/universal-android-ssl-pinning-bypass")
                
                self.root.after(0, self.execution_complete, f"❌ Execution failed: {error_msg}")
            
            finally:
                self.frida_process = None
        
        threading.Thread(target=execute, daemon=True).start()
    
    def append_output(self, text):
        """Append text to output"""
        self.output_text.insert('end', text)
        self.output_text.see('end')
    
    def execution_complete(self, message):
        """Handle execution completion"""
        self.append_output(f"\n\n{message}\n")
        self.log(message)
        self.is_running = False
        self.execute_btn.config(state='normal')
        self.update_execution_ui()
    
    def stop_execution(self):
        """Stop current execution"""
        if self.frida_process and self.is_running:
            try:
                self.frida_process.terminate()
                self.log("Execution stopped by user", "warning")
                self.append_output("\n\n[INFO] Execution stopped by user\n")
                self.is_running = False
                self.execute_btn.config(state='normal')
                self.update_execution_ui()
            except:
                pass
    
    def clear_output(self):
        """Clear output window"""
        self.output_text.delete('1.0', 'end')
    
    def save_output(self):
        """Save output to file"""
        output = self.output_text.get('1.0', 'end')
        if not output.strip():
            messagebox.showwarning("Warning", "No output to save")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(output)
                self.log(f"Output saved to {filename}", "success")
            except Exception as e:
                self.log(f"Failed to save output: {str(e)}", "error")
    
    def open_script_folder(self):
        """Open script folder"""
        script_dir = "scripts"
        if not os.path.exists(script_dir):
            os.makedirs(script_dir)
        
        if self.os_type == "Windows":
            os.startfile(script_dir)
        else:
            import subprocess
            subprocess.run(['xdg-open', script_dir])
    
    def open_adb_shell(self):
        """Open ADB shell"""
        if self.selected_device:
            if self.os_type == "Windows":
                subprocess.Popen(f'start cmd /k adb -s {self.selected_device} shell', shell=True)
            else:
                subprocess.Popen(f'x-terminal-emulator -e "adb -s {self.selected_device} shell"', shell=True)
        else:
            if self.os_type == "Windows":
                subprocess.Popen('start cmd /k adb shell', shell=True)
            else:
                subprocess.Popen('x-terminal-emulator -e "adb shell"', shell=True)
    
    def open_frida_console(self):
        """Open Frida console"""
        if self.os_type == "Windows":
            subprocess.Popen('start cmd /k frida-ps -Uai', shell=True)
        else:
            subprocess.Popen('x-terminal-emulator -e "frida"', shell=True)
    
    def open_codeshare_web(self):
        """Open CodeShare website"""
        webbrowser.open("https://codeshare.frida.re")
    
    def install_frida_pc(self):
        """Install Frida on PC"""
        self.log("Installing Frida on PC...")
        
        def install():
            try:
                result = self.run_command("pip install frida-tools", timeout=120)
                if result.returncode == 0:
                    try:
                        frida_version = self.run_command("frida --version").stdout.strip()
                        self.log(f"Frida v{frida_version} installed successfully", "success")
                    except:
                        self.log("Frida installed but version check failed", "success")
                else:
                    self.log(f"Installation failed: {result.stderr}", "error")
            except Exception as e:
                self.log(f"Installation failed: {str(e)}", "error")
        
        threading.Thread(target=install, daemon=True).start()

# ============================================================================
# MAIN
# ============================================================================

def main():
    root = tk.Tk()
    app = FridaScriptRunner(root)
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    # Handle close
    def on_closing():
        if app.is_running:
            if messagebox.askyesno("Quit", "Script is running. Stop and quit?"):
                app.stop_execution()
                root.after(1000, root.destroy)
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Keyboard shortcuts
    root.bind('<Control-r>', lambda e: app.detect_devices())
    root.bind('<Control-s>', lambda e: app.scan_scripts())
    root.bind('<Control-e>', lambda e: app.execute_script())
    root.bind('<Control-a>', lambda e: app.auto_setup_device())
    root.bind('<Control-q>', lambda e: root.quit())
    
    root.mainloop()

if __name__ == "__main__":

    main()

