
# Crunchy Thief

Crunchy Thief is a multi-threaded account checker designed to validate Crunchyroll account credentials. This tool reads email:password combinations from a specified file, attempts to authenticate them using the Crunchyroll API, and classifies the accounts as valid, free, or invalid.

## Features
- **Multi-Threaded Processing**: Utilizes Python's `concurrent.futures.ThreadPoolExecutor` for efficient, concurrent login attempts.
- **Random User-Agent Rotation**: Implements the `fake_useragent` library to randomize User-Agent strings, reducing the likelihood of being rate-limited.
- **Error Handling**: Robust handling of HTTP errors, including rate limits and invalid credentials.
- **Result Logging**: Saves results in categorized text files for easy access and review.
- **Logging Support**: Logs all actions and errors to a log file for troubleshooting and monitoring purposes.

## Usage
1. Install required packages:
   ```bash
   pip install fake_useragent colorama


## SETUP
```
git clone https://github.com/AnonCatalyst/Crunchy-Thief
cd Crunchy-Thief
pip install -r requirements.txt --break-system-packages
python3 crunchy.py
```
