# HashAnalyzer

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.6%2B-brightgreen)

A comprehensive hash analysis tool that supports multiple algorithms including MD5, SHA-1, SHA-256, SHA-512, and bcrypt. This tool is designed for **educational purposes only** to demonstrate hash analysis techniques and password security concepts.

## Features

- Support for multiple hash types (MD5, SHA-1, SHA-256, SHA-512, bcrypt)
- Automatic hash type detection
- Multiple attack methods:
  - Dictionary attack using wordlists
  - Hybrid attack with common password modifications
  - Brute force attack with multithreading support
- Progress tracking with ETA
- Detailed statistics and logging
- Customizable character sets and rules
- Results saving for future reference

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/HashAnalyzer.git
cd HashAnalyzer

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt

# Create wordlists directory
mkdir -p wordlists
```

## Dependencies

- Python 3.6+
- bcrypt
- tqdm
- colorama

## Usage

### Basic Usage

```bash
python hash_analyzer.py <HASH>
```

The tool will attempt to detect the hash type and run all analysis methods.

### Specify Hash Type

```bash
python hash_analyzer.py <HASH> --type md5
```

### Specify Wordlist

```bash
python hash_analyzer.py <HASH> --wordlist /path/to/wordlist.txt
```

### Choose Attack Methods

```bash
python hash_analyzer.py <HASH> --methods dictionary hybrid
```

### Configure Brute Force Attack

```bash
python hash_analyzer.py <HASH> --max-length 6 --charset "abcdefghijklmnopqrstuvwxyz0123456789"
```

### Adjust Parallelism

```bash
python hash_analyzer.py <HASH> --processes 8
```

## Creating Your Wordlist

The tool requires a wordlist for dictionary attacks. You can create your own or download common ones like `rockyou.txt`.

> **Note:** For educational purposes, you can use smaller wordlists during development.

## Configuration

You can customize default settings by editing the `config.json` file:

```json
{
  "default_wordlist": "wordlists/rockyou.txt",
  "max_processes": 4,
  "max_brute_force_length": 8,
  "default_charset": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  "save_results": true,
  "results_file": "hash_results.json"
}
```

## Examples

### Analyze an MD5 Hash

```bash
python hash_analyzer.py 5f4dcc3b5aa765d61d8327deb882cf99
```

### Analyze a bcrypt Hash

```bash
python hash_analyzer.py '$2a$12$K3JNi5vQMQoi5lMEYvHSfOSqSKnlUKASwzf6.d8cK0MjISYVkEs3e' --type bcrypt
```

### Dictionary Attack Only

```bash
python hash_analyzer.py <HASH> --methods dictionary
```

## Disclaimer

This tool is provided for **educational purposes only**. It is designed to demonstrate hash analysis techniques and to help understand password security concepts. The authors are not responsible for any misuse of this tool. Always ensure you have proper authorization before analyzing any hash.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
