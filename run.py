#!/usr/bin/env python3
"""
adcAM Sniffer - Network Packet Analysis Tool
Entry point for the application with enhanced error handling
"""
import sys
import os


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:

        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def main():
    """Main entry point with comprehensive error handling"""
    try:

        if sys.version_info < (3, 8):
            print("Error: Python 3.8 or higher is required.")
            print(f"Current version: {sys.version}")
            input("Press Enter to exit...")
            sys.exit(1)


        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)


        try:
            from app import application
            print("Starting adcAM Sniffer...")
            print("Note: This application requires administrator privileges on Windows.")
            application.run_app()

        except ImportError as e:
            print(f"Import Error: {e}")
            print("Please ensure all required packages are installed:")
            print("pip install -r requirements.txt")
            input("Press Enter to exit...")
            sys.exit(1)

        except KeyboardInterrupt:
            print("\nApplication interrupted by user.")
            sys.exit(0)

        except Exception as e:
            print(f"Application Error: {e}")
            print("\nTroubleshooting tips:")
            print("1. Run as Administrator (Windows) or with sudo (Linux/Mac)")
            print("2. Install Npcap or WinPcap (Windows)")
            print("3. Check firewall and antivirus settings")
            print("4. Ensure all dependencies are installed")
            input("Press Enter to exit...")
            sys.exit(1)

    except Exception as e:
        print(f"Critical startup error: {e}")
        input("Press Enter to exit...")
        sys.exit(1)


if __name__ == '__main__':
    main()