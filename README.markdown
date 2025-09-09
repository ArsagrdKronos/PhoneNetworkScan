# Ethical Phone Registry & Scanner

## Overview
The **Ethical Phone Registry & Scanner** is a Python-based tool designed for ethical phone number scanning, registration, and management. It provides functionalities for validating phone numbers, checking for potential scams, registering numbers with associated metadata, and exporting data to CSV. The tool emphasizes privacy and ethical use, intended for security purposes and fraud detection.

**Creator**: ArsagrdKronos

## Features
- **Single Number Scanning**: Validate and retrieve detailed information about a phone number, including country, carrier, geolocation, and number type.
- **Batch Scanning**: Process multiple phone numbers at once for efficient analysis.
- **Scam Checking**: Generate search URLs for checking if a number is associated with scams or spam.
- **Number Registration**: Store phone number details in a local JSON registry with user-provided notes, names, signal strength, and optional IP address.
- **IP Address Checking**: Retrieve geolocation and ISP details for an IP address.
- **Search Functionality**: Search registered numbers by notes or specific fields (e.g., country, carrier).
- **Data Export**: Export registry data to a CSV file for further analysis.
- **Entry Deletion**: Remove specific phone numbers from the registry.
- **User-Friendly Menu**: Interactive CLI menu with arrow key navigation, colorful output, and ASCII icons.
- **Logging**: Detailed logs saved to `registry_log.txt` for all actions.
- **Ethical Use**: Designed for security and fraud detection, respecting user privacy.

## Requirements
To run the script, install the following Python libraries:
```bash
pip install phonenumbers keyboard pandas tabulate colorama requests
```

## Installation
1. Clone or download the script (`RegisterPhone.py`).
2. Ensure Python 3.6+ is installed.
3. Install the required libraries using the command above.
4. Run the script:
   ```bash
   python RegisterPhone.py
   ```

## Usage
1. Launch the script to access the interactive menu.
2. Use the **Up** and **Down** arrow keys to navigate options, **Enter** to select, and **Esc** to exit.
3. Available options:
   - **Scan Single Number**: Enter a phone number (e.g., `+48123456789`) to validate and retrieve details.
   - **Batch Scan Numbers**: Input comma-separated numbers for bulk scanning.
   - **Check for Scams**: Generate a search URL to check if a number is reported as a scam.
   - **Register Number**: Save a number with optional notes, name, signal strength, and IP address.
   - **View Registered Numbers**: Display all registered numbers in a tabulated format.
   - **Check if Registered**: Verify if a number exists in the registry.
   - **Search by Notes**: Search entries by keywords in notes.
   - **Search by Field**: Search entries by specific fields (e.g., country, carrier).
   - **Check IP Address**: Retrieve details for an IP address.
   - **Export to CSV**: Export registry data to a CSV file (default: `phone_registry_export.csv`).
   - **Delete Entry**: Remove a number from the registry.
   - **Exit**: Close the application.

## Data Storage
- **Registry**: Stored locally in `phone_registry.json`.
- **Logs**: Detailed logs saved in `registry_log.txt`.
- **Export**: Data can be exported to a CSV file (default: `phone_registry_export.csv`).

## Example
```bash
$ python PhoneNetworkScan.py
```
- Select "Scan Single Number" and enter `+48123456789`.
- View detailed output including country, carrier, and geolocation.
- Register the number with optional notes and IP address.
- Export the registry to CSV for further analysis.

## Ethical Use
This tool is intended for **ethical purposes only**, such as:
- Verifying phone numbers for security.
- Detecting potential fraud or spam.
- Managing contact information responsibly.

**Do not use this tool for unauthorized tracking, harassment, or any illegal activities.** Always respect privacy laws and regulations.

## Notes
- The script supports country codes `+1` to `+48`. Additional codes can be added by modifying `supported_countries` in the `PhoneScanner` class.
- IP address checking uses the `ip-api.com` service, which may have usage limits.
- The `keyboard` library requires root/admin privileges on some systems for arrow key navigation.
- All data is stored locally, and no external servers are used for storage.

## Logging
All actions (scans, registrations, searches, etc.) are logged in `registry_log.txt` with timestamps and details for auditing purposes.

## Limitations
- Phone number metadata (e.g., name) is limited to user-provided input to respect privacy.
- MAC address and signal strength are not automatically retrieved (device-specific) and rely on user input.
- Scam checking provides a search URL rather than direct results to avoid unethical data scraping.

## License
This project is provided as-is for educational and ethical use. No warranty is provided. Use responsibly.

## Contact
For issues or suggestions, contact **ArsagrdKronos** via [insert contact method, e.g., GitHub, email].
