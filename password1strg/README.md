# PASS1STRG - Password Strength Auditor

A comprehensive password strength analysis tool that helps you evaluate the security of your passwords, detect common weaknesses, and generate detailed audit reports.

## Features

- **Password Analysis**: Evaluate individual passwords for strength, length, character variety, and common patterns
- **Batch Processing**: Analyze multiple passwords at once
- **Weakness Detection**: Identifies common passwords, keyboard patterns, repeated characters, and username matches
- **Security Scoring**: Provides a score from 0-100 with strength ratings (Very Weak, Weak, Moderate, Strong)
- **Crack Time Estimation**: Estimates time required to crack passwords
- **Report Generation**: Creates HTML and text reports with statistics and recommendations
- **Duplicate Detection**: Checks for password reuse across accounts
- **GUI Interface**: User-friendly graphical interface for easy operation
- **CLI Interface**: Command-line interface for scripting and automation


## Installation

### Prerequisites
- Python 3.6 or higher
- Tkinter (usually included with Python installations)

### Install Dependencies
The program uses Python's standard library, so no additional dependencies are required for basic functionality. However, if you're running the GUI version, ensure Tkinter is available.

For Windows users, Tkinter is included by default.
For Linux/Mac, you may need to install it separately:
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# macOS
# Tkinter is included with Python from python.org
```

## Usage

### Running the Program

#### GUI Mode (Default)
Simply run the script to launch the graphical interface:
```bash
python password1strg.py
```

#### CLI Mode
The script includes a command-line interface. To access it, you may need to modify the `__main__` block or run the `main()` function directly.

### Using the GUI

1. **Add Passwords**: Enter account names, usernames, and passwords manually
2. **Load Sample Data**: Use pre-loaded sample passwords for testing
3. **Run Audit**: Analyze all entered passwords and generate reports
4. **View Results**: See detailed analysis and statistics
5. **Clear Data**: Remove all entered passwords

### Using the CLI

The CLI provides a menu-driven interface:

1. Add passwords manually
2. Load sample data
3. Run audit & generate reports
4. View current passwords
5. Clear all passwords
6. Exit

### Sample Output

```
============================================================
                                                            
     PASS1STRG - Password Strength Auditor                 
     Analyze | Detect Weaknesses | Generate Reports        
                                                            
============================================================

 STRENGTH DISTRIBUTION:
----------------------------------
  Strong    : 2 ##
  Moderate  : 3 ###
  Weak      : 1 #
  Very Weak : 2 ##

 DETAILED RESULTS:
----------------------------------
[+] Gmail
   Score: 85/100 (Strong)
   Length: 12 chars
   Crack time: Years to decades
   Issues: None

[!] Netflix
   Score: 25/100 (Very Weak)
   Length: 6 chars
   Crack time: Minutes to hours
   Issues: Too short, Common password, No uppercase, No symbols
```

## Report Formats

### HTML Report
- Interactive web-based report
- Color-coded scores
- Charts and statistics
- Downloadable and shareable

### Text Report
- Plain text format
- Detailed analysis
- Security recommendations
- Suitable for logging

## Security Recommendations

1. **Use Unique Passwords**: Never reuse passwords across accounts
2. **Length Matters**: Aim for 12+ characters minimum
3. **Character Variety**: Include uppercase, lowercase, numbers, and symbols
4. **Avoid Patterns**: Don't use keyboard sequences or common words
5. **Password Manager**: Use tools like Bitwarden, 1Password, or LastPass
6. **Two-Factor Authentication**: Enable 2FA wherever possible
7. **Regular Updates**: Change passwords periodically

## Algorithm Details

### Scoring System
- **Length**: 8+ characters required, bonus for longer passwords
- **Character Types**: Points for uppercase, lowercase, digits, symbols
- **Common Passwords**: Heavy penalty for dictionary words
- **Patterns**: Deductions for sequential characters
- **Reuse**: Warnings for duplicate passwords

### Crack Time Estimation
Based on common attack methods:
- Dictionary attacks
- Brute force
- Rainbow tables
- Hybrid approaches

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is open source. Please check the license file for details.

## Disclaimer

This tool is for educational and security awareness purposes. Always follow your organization's password policies and use strong, unique passwords for all accounts.

## Version History

- v1.0: Initial release with basic password analysis
- v1.1: Added GUI interface and report generation
- v1.2: Improved scoring algorithm and crack time estimation

---
