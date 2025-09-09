# RegisterPhone.py - Zaawansowany Skrypt do Etycznego Rejestrowania i Skanowania Numerów Telefonów
# Ulepszenia: Logi w txt z pełnymi szczegółami, sprawdzanie adresu IP, kolory, ikony ASCII, baner.
# Funkcjonalności: Skanowanie numerów, rejestracja, wyszukiwanie, eksport CSV, usuwanie wpisów, sprawdzanie IP.
# Etyczne użycie: Dla bezpieczeństwa i wykrywania oszustw, z zachowaniem prywatności.
# Wymagane biblioteki: pip install phonenumbers keyboard pandas tabulate colorama requests
# Dane przechowywane lokalnie w phone_registry.json, logi w registry_log.txt, eksport w CSV.

import os
import json
import keyboard
import phonenumbers
from phonenumbers import geocoder, carrier, timezone, PhoneNumberType
from datetime import datetime
import re
import pandas as pd
import hashlib
import logging
from tabulate import tabulate
from colorama import init, Fore, Style
import requests

# Inicjalizacja colorama
init(autoreset=True)

# Konfiguracja logowania
logging.basicConfig(filename='registry_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Baner ASCII
BANNER = f"""
{Fore.CYAN + Style.BRIGHT}
   _____ _          
  |  __ (_)         
  | |__) |__  _ __   ___  ___ 
  |  ___/ _ \\| '_ \\ / __|/ __|
  | |  | |  | | | | | (__| (__ 
  |_|  |_|\\___|_| |_| \\___|\\___|
{Fore.YELLOW}Creator: Kro3nos{Style.RESET_ALL}
"""

# Ikony ASCII dla menu i wyników
ICONS = {
    "menu": "📋",
    "scan": "🔍",
    "batch": "📜",
    "scam": "⚠️",
    "register": "✍️",
    "view": "👀",
    "check": "✅",
    "search": "🔎",
    "export": "💾",
    "delete": "🗑️",
    "ip_check": "🌐",
    "exit": "🚪"
}

class PhoneScanner:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.supported_countries = list(range(1, 49))
        self.number_type_map = {
            PhoneNumberType.MOBILE: "Mobile",
            PhoneNumberType.FIXED_LINE: "Fixed Line",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
            PhoneNumberType.TOLL_FREE: "Toll Free",
            PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            PhoneNumberType.SHARED_COST: "Shared Cost",
            PhoneNumberType.VOIP: "VoIP",
            PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
            PhoneNumberType.PAGER: "Pager",
            PhoneNumberType.UAN: "UAN",
            PhoneNumberType.VOICEMAIL: "Voicemail",
            PhoneNumberType.UNKNOWN: "Unknown"
        }

    def validate_number(self, number_str):
        try:
            parsed = phonenumbers.parse(number_str)
            is_valid = phonenumbers.is_valid_number(parsed)
            is_possible = phonenumbers.is_possible_number(parsed)
            country_code = parsed.country_code
            national_number = parsed.national_number
            
            if country_code not in self.supported_countries:
                return {"error": f"Unsupported country code: +{country_code}. Supported: +1 to +48."}
            
            number_type = phonenumbers.number_type(parsed)
            number_type_str = self.number_type_map.get(number_type, "Unknown")
            country = geocoder.country_name_for_number(parsed, "en") or "Unknown"
            country_iso = phonenumbers.region_code_for_number(parsed) or "Unknown"
            possible_formats = [
                phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            ]
            
            result = {
                "valid": is_valid,
                "possible": is_possible,
                "country_code": f"+{country_code}",
                "national_number": str(national_number),
                "full_international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "full_e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                "possible_formats": possible_formats,
                "country": country,
                "country_iso": country_iso,
                "scan_time": datetime.now().isoformat(),
                "carrier": carrier.name_for_number(parsed, "en") or "Unknown",
                "geolocation": geocoder.description_for_number(parsed, "en") or "Unknown",
                "timezones": list(timezone.time_zones_for_number(parsed)) or ["Unknown"],
                "number_type": number_type_str,
                "name": "Not available (ethical privacy; use user_provided_name for manual input)",
                "user_provided_name": "",
                "mac_address": "N/A (MAC address is device-specific, not applicable to phone numbers)",
                "signal_strength": "N/A (requires device access; use user_reported_signal for manual input)",
                "user_reported_signal": "",
                "ip_address": ""  # Pole dla opcjonalnego IP
            }
            
            # Logowanie szczegółów
            log_message = (
                f"Number Scan:\n"
                f"  Number: {result['full_e164']}\n"
                f"  Valid: {is_valid}\n"
                f"  Type: {number_type_str}\n"
                f"  Country: {country} ({country_iso})\n"
                f"  Carrier: {result['carrier']}\n"
                f"  Geolocation: {result['geolocation']}\n"
                f"  Timezones: {', '.join(result['timezones'])}\n"
                f"  Scan Time: {result['scan_time']}\n"
                f"{'-'*50}"
            )
            logging.info(log_message)
            return result
        except phonenumbers.NumberParseException as e:
            logging.error(f"Invalid number format: {str(e)}")
            return {"error": f"Invalid number format: {str(e)}"}

    def check_for_scams(self, number_str, search_engine="google"):
        formatted_number = re.sub(r'[^\d+]', '', number_str)
        query = f"is phone number {formatted_number} a scam or spam"
        search_url = f"https://www.google.com/search?q={query.replace(' ', '+')}" if search_engine == "google" else f"https://www.bing.com/search?q={query.replace(' ', '+')}"
        result = {
            "scam_check_advice": "Visit the URL to check scam reports.",
            "suggested_search_url": search_url,
            "warning": "For safety only. Do not misuse."
        }
        logging.info(f"Scam check initiated for {formatted_number}")
        return result

    def check_ip_address(self, ip_address):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}")
            data = response.json()
            if data["status"] == "success":
                result = {
                    "ip_address": ip_address,
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "as": data.get("as", "Unknown"),
                    "query_time": datetime.now().isoformat()
                }
                log_message = (
                    f"IP Check:\n"
                    f"  IP: {ip_address}\n"
                    f"  Country: {result['country']} ({result['country_code']})\n"
                    f"  Region: {result['region']}\n"
                    f"  City: {result['city']}\n"
                    f"  ISP: {result['isp']}\n"
                    f"  Query Time: {result['query_time']}\n"
                    f"{'-'*50}"
                )
                logging.info(log_message)
                return result
            else:
                logging.error(f"IP check failed: {data.get('message', 'Unknown error')}")
                return {"error": f"IP check failed: {data.get('message', 'Unknown error')}"}
        except Exception as e:
            logging.error(f"IP check error: {str(e)}")
            return {"error": f"IP check error: {str(e)}"}

    def batch_scan(self, numbers_list):
        results = []
        for num in numbers_list:
            result = self.validate_number(num)
            if "error" not in result:
                result.update(self.check_for_scams(num))
            results.append(result)
        logging.info(f"Batch scan completed for {len(numbers_list)} numbers")
        return results

class PhoneRegistry:
    def __init__(self, registry_file="phone_registry.json"):
        self.registry_file = registry_file
        self.registry = self.load_registry()

    def load_registry(self):
        if os.path.exists(self.registry_file):
            try:
                with open(self.registry_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Failed to load registry: {str(e)}")
                return {}
        return {}

    def save_registry(self):
        try:
            with open(self.registry_file, 'w') as f:
                json.dump(self.registry, f, indent=2)
            logging.info("Registry saved successfully")
        except Exception as e:
            logging.error(f"Failed to save registry: {str(e)}")

    def hash_number(self, number):
        return hashlib.sha256(number.encode()).hexdigest()

    def register_number(self, number_str, notes="", user_provided_name="", user_reported_signal="", ip_address=""):
        scan_result = PhoneScanner().validate_number(number_str)
        if "error" in scan_result:
            logging.error(f"Registration failed: {scan_result['error']}")
            return scan_result
        
        user_provided_name = user_provided_name.strip()[:50] or ""
        user_reported_signal = user_reported_signal.strip()[:20] or ""
        notes = notes.strip()[:200] or ""
        ip_address = ip_address.strip()[:45] or ""  # Max 45 dla IPv6
        
        hashed_number = self.hash_number(scan_result["full_e164"])
        scan_result["user_provided_name"] = user_provided_name
        scan_result["user_reported_signal"] = user_reported_signal
        scan_result["ip_address"] = ip_address
        scan_result["last_scanned"] = datetime.now().isoformat()
        
        ip_info = {}
        if ip_address:
            ip_info = PhoneScanner().check_ip_address(ip_address)
        
        entry = {
            "hashed_number": hashed_number,
            "original_number": scan_result["full_e164"],
            "scan_data": scan_result,
            "ip_info": ip_info if "error" not in ip_info else {},
            "notes": notes,
            "registered_at": datetime.now().isoformat()
        }
        self.registry[hashed_number] = entry
        self.save_registry()
        logging.info(
            f"Number {scan_result['full_e164']} registered with hash {hashed_number}, "
            f"Name={user_provided_name}, Signal={user_reported_signal}, IP={ip_address}, Notes={notes}"
        )
        return {"success": True, "message": f"Number registered successfully.", "entry": entry}

    def get_registered_numbers(self):
        return list(self.registry.values())

    def check_if_registered(self, number_str):
        scan_result = PhoneScanner().validate_number(number_str)
        if "error" in scan_result:
            return scan_result
        hashed_number = self.hash_number(scan_result["full_e164"])
        if hashed_number in self.registry:
            logging.info(f"Number {scan_result['full_e164']} found in registry")
            return {"registered": True, "entry": self.registry[hashed_number]}
        logging.info(f"Number {scan_result['full_e164']} not found in registry")
        return {"registered": False}

    def search_by_notes(self, keyword):
        results = [entry for entry in self.registry.values() if keyword.lower() in entry["notes"].lower()]
        logging.info(f"Search by notes with keyword '{keyword}' returned {len(results)} results")
        return results

    def search_by_field(self, field, keyword):
        results = []
        for entry in self.registry.values():
            value = entry["scan_data"].get(field, "")
            if isinstance(value, str) and keyword.lower() in value.lower():
                results.append(entry)
        logging.info(f"Search by {field} with keyword '{keyword}' returned {len(results)} results")
        return results

    def delete_entry(self, number_str):
        scan_result = PhoneScanner().validate_number(number_str)
        if "error" in scan_result:
            logging.error(f"Deletion failed: {scan_result['error']}")
            return scan_result
        hashed_number = self.hash_number(scan_result["full_e164"])
        if hashed_number in self.registry:
            del self.registry[hashed_number]
            self.save_registry()
            logging.info(f"Number {scan_result['full_e164']} deleted from registry")
            return {"success": True, "message": f"Number {number_str} deleted successfully."}
        logging.info(f"Number {scan_result['full_e164']} not found for deletion")
        return {"error": "Number not found in registry."}

    def export_to_csv(self, output_file="phone_registry_export.csv"):
        if not self.registry:
            logging.warning("Export failed: Registry is empty")
            return {"error": "Registry is empty"}
        data = [{
            "Hashed Number": entry["hashed_number"],
            "Original Number": entry["original_number"],
            "Country": entry["scan_data"]["country"],
            "Country ISO": entry["scan_data"]["country_iso"],
            "Carrier": entry["scan_data"]["carrier"],
            "Geolocation": entry["scan_data"]["geolocation"],
            "Number Type": entry["scan_data"]["number_type"],
            "User Provided Name": entry["scan_data"]["user_provided_name"],
            "User Reported Signal": entry["scan_data"]["user_reported_signal"],
            "IP Address": entry["scan_data"]["ip_address"],
            "IP Country": entry["ip_info"].get("country", ""),
            "IP ISP": entry["ip_info"].get("isp", ""),
            "Notes": entry["notes"],
            "Registered At": entry["registered_at"],
            "Last Scanned": entry["scan_data"]["last_scanned"]
        } for entry in self.registry.values()]
        df = pd.DataFrame(data)
        df.to_csv(output_file, index=False)
        logging.info(f"Registry exported to {output_file}")
        return {"success": True, "message": f"Exported to {output_file}"}

class SimpleModernMenu:
    def __init__(self):
        self.scanner = PhoneScanner()
        self.registry = PhoneRegistry()
        self.menu_options = [
            ("Scan Single Number", ICONS["scan"]),
            ("Batch Scan Numbers", ICONS["batch"]),
            ("Check for Scams", ICONS["scam"]),
            ("Register Number", ICONS["register"]),
            ("View Registered Numbers", ICONS["view"]),
            ("Check if Registered", ICONS["check"]),
            ("Search by Notes", ICONS["search"]),
            ("Search by Field", ICONS["search"]),
            ("Check IP Address", ICONS["ip_check"]),
            ("Export to CSV", ICONS["export"]),
            ("Delete Entry", ICONS["delete"]),
            ("Exit", ICONS["exit"])
        ]
        self.selected_index = 0
        self.running = True

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_menu(self):
        self.clear_screen()
        print(BANNER)
        print(f"{Fore.CYAN + Style.BRIGHT}=== Ethical Phone Registry & Scanner Menu ==={Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Use ↑/↓ arrows to navigate, Enter to select, Esc to exit{Style.RESET_ALL}")
        print(f"{Fore.CYAN}================================{Style.RESET_ALL}\n")
        for i, (option, icon) in enumerate(self.menu_options):
            if i == self.selected_index:
                print(f"{Fore.GREEN + Style.BRIGHT}>> {icon} {option} <<{Style.RESET_ALL}")
            else:
                print(f"   {icon} {option}")

    def display_result(self, result):
        if "error" in result:
            print(f"{Fore.RED + Style.BRIGHT}{ICONS['scam']} Error: {result['error']}{Style.RESET_ALL}")
            return
        table = [[key, value] for key, value in result.items() if key not in ["possible_formats", "timezones"]]
        table += [["Timezones", ", ".join(result["timezones"])]]
        table += [["Possible Formats", ", ".join(result["possible_formats"])]]
        print(f"\n{Fore.CYAN + Style.BRIGHT}{ICONS['scan']} Results:{Style.RESET_ALL}")
        print(tabulate(table, headers=["Field", "Value"], tablefmt="fancy_grid"))

    def display_list_results(self, results):
        if not results:
            print(f"\n{Fore.YELLOW}{ICONS['view']} No results to display.{Style.RESET_ALL}")
            return
        table = []
        for entry in results:
            scan_data = entry.get("scan_data", entry)
            table.append([
                scan_data.get("full_e164", "N/A"),
                scan_data.get("country", "Unknown"),
                scan_data.get("country_iso", "Unknown"),
                scan_data.get("carrier", "Unknown"),
                scan_data.get("geolocation", "Unknown"),
                scan_data.get("number_type", "Unknown"),
                scan_data.get("user_provided_name", ""),
                scan_data.get("user_reported_signal", ""),
                scan_data.get("ip_address", ""),
                entry.get("notes", ""),
                entry.get("registered_at", scan_data.get("scan_time", ""))
            ])
        print(f"\n{Fore.CYAN + Style.BRIGHT}{ICONS['view']} Results:{Style.RESET_ALL}")
        print(tabulate(table, headers=["Number", "Country", "ISO", "Carrier", "Geolocation", "Type", "Name", "Signal", "IP", "Notes", "Date"], tablefmt="fancy_grid"))

    def handle_input(self):
        while self.running:
            self.display_menu()
            event = keyboard.read_event(suppress=True)
            if event.event_type == keyboard.KEY_DOWN:
                if event.name == 'up' and self.selected_index > 0:
                    self.selected_index -= 1
                elif event.name == 'down' and self.selected_index < len(self.menu_options) - 1:
                    self.selected_index += 1
                elif event.name == 'enter':
                    self.execute_option()
                elif event.name == 'esc':
                    self.running = False
                    self.clear_screen()
                    print(f"{Fore.GREEN}{ICONS['exit']} Exiting Phone Registry. Stay safe!{Style.RESET_ALL}")
                    break

    def execute_option(self):
        self.clear_screen()
        option, icon = self.menu_options[self.selected_index]
        print(f"{Fore.CYAN + Style.BRIGHT}{icon} Selected: {option}{Style.RESET_ALL}\n")

        if option == "Scan Single Number":
            number = input(f"{Fore.YELLOW}Enter phone number (e.g., +48123456789): {Style.RESET_ALL}")
            result = self.scanner.validate_number(number)
            self.display_result(result)
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "Batch Scan Numbers":
            numbers_input = input(f"{Fore.YELLOW}Enter phone numbers (comma-separated, e.g., +48123456789,+12025550123): {Style.RESET_ALL}")
            numbers = [num.strip() for num in numbers_input.split(',')]
            results = self.scanner.batch_scan(numbers)
            self.display_list_results(results)
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "Check for Scams":
            number = input(f"{Fore.YELLOW}Enter phone number to check for scams: {Style.RESET_ALL}")
            result = self.scanner.check_for_scams(number)
            self.display_result(result)
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "Register Number":
            number = input(f"{Fore.YELLOW}Enter phone number to register: {Style.RESET_ALL}")
            notes = input(f"{Fore.YELLOW}Enter notes (optional, e.g., 'suspected scam'): {Style.RESET_ALL}")
            user_name = input(f"{Fore.YELLOW}Enter user-provided name (optional, e.g., 'Contact: Jan'): {Style.RESET_ALL}")
            user_signal = input(f"{Fore.YELLOW}Enter user-reported signal strength (optional, e.g., 'Weak'): {Style.RESET_ALL}")
            ip_address = input(f"{Fore.YELLOW}Enter associated IP address (optional, e.g., '192.168.1.1'): {Style.RESET_ALL}")
            result = self.registry.register_number(number, notes, user_name, user_signal, ip_address)
            self.display_result(result)
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "View Registered Numbers":
            registered = self.registry.get_registered_numbers()
            self.display_list_results(registered)
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "Check if Registered":
            number = input(f"{Fore.YELLOW}Enter phone number to check: {Style.RESET_ALL}")
            result = self.registry.check_if_registered(number)
            self.display_result(result.get("entry", result))
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "Search by Notes":
            keyword = input(f"{Fore.YELLOW}Enter keyword to search in notes (e.g., 'scam'): {Style.RESET_ALL}")
            results = self.registry.search_by_notes(keyword)
            self.display_list_results(results)
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "Search by Field":
            field = input(f"{Fore.YELLOW}Enter field to search (e.g., 'country', 'carrier', 'number_type'): {Style.RESET_ALL}")
            keyword = input(f"{Fore.YELLOW}Enter keyword to search in {field}: {Style.RESET_ALL}")
            results = self.registry.search_by_field(field, keyword)
            self.display_list_results(results)
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "Check IP Address":
            ip_address = input(f"{Fore.YELLOW}Enter IP address to check (e.g., '192.168.1.1'): {Style.RESET_ALL}")
            result = self.scanner.check_ip_address(ip_address)
            self.display_result(result)
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "Export to CSV":
            output_file = input(f"{Fore.YELLOW}Enter CSV filename (default: phone_registry_export.csv): {Style.RESET_ALL}") or "phone_registry_export.csv"
            result = self.registry.export_to_csv(output_file)
            self.display_result(result)
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "Delete Entry":
            number = input(f"{Fore.YELLOW}Enter phone number to delete: {Style.RESET_ALL}")
            result = self.registry.delete_entry(number)
            self.display_result(result)
            input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

        elif option == "Exit":
            self.running = False
            print(f"{Fore.GREEN}{ICONS['exit']} Exiting Phone Registry. Stay safe!{Style.RESET_ALL}")

    def run(self):
        print(BANNER)
        print(f"{Fore.GREEN}Starting Ethical Phone Registry & Scanner...{Style.RESET_ALL}")
        logging.info("Application started")
        self.handle_input()

# Główny entry point
if __name__ == "__main__":
    try:
        menu = SimpleModernMenu()
        menu.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Program terminated by user.{Style.RESET_ALL}")
        logging.info("Program terminated by user")
    except Exception as e:
        print(f"\n{Fore.RED}An error occurred: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Application error: {str(e)}")