# HashAnalyzer - A multi-algorithm hash analysis tool
# For educational purposes only

import hashlib
import argparse
import os
import time
import itertools
import string
import bcrypt
import multiprocessing
from tqdm import tqdm
import json
import logging
import sys
from colorama import Fore, Style, init

init(autoreset=True)  # Initialize colorama

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("hash_analyzer.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("HashAnalyzer")

class HashAnalyzer:
    """
    A tool for analyzing and attempting to recover passwords from hash values
    using dictionary attacks and other methods.
    """
    
    def __init__(self):
        self.supported_algorithms = {
            'md5': self._md5_hash,
            'sha1': self._sha1_hash,
            'sha256': self._sha256_hash,
            'sha512': self._sha512_hash,
            'bcrypt': self._bcrypt_hash,
        }
        
        self.statistics = {
            'attempts': 0,
            'start_time': None,
            'end_time': None,
            'method_used': None,
            'success': False
        }
        
        # Load configuration if exists
        self.config = self._load_config()
    
    def _load_config(self):
        """Load configuration file if exists, otherwise use defaults"""
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
        default_config = {
            'default_wordlist': os.path.join(os.path.dirname(__file__), 'wordlists', 'rockyou.txt'),
            'max_processes': multiprocessing.cpu_count(),
            'max_brute_force_length': 8,
            'default_charset': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
            'save_results': True,
            'results_file': 'hash_results.json'
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            return default_config
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return default_config
    
    def _md5_hash(self, text):
        """Generate MD5 hash for the given text"""
        return hashlib.md5(text.encode()).hexdigest()
    
    def _sha1_hash(self, text):
        """Generate SHA1 hash for the given text"""
        return hashlib.sha1(text.encode()).hexdigest()
    
    def _sha256_hash(self, text):
        """Generate SHA256 hash for the given text"""
        return hashlib.sha256(text.encode()).hexdigest()
    
    def _sha512_hash(self, text):
        """Generate SHA512 hash for the given text"""
        return hashlib.sha512(text.encode()).hexdigest()
    
    def _bcrypt_hash(self, text, salt=None):
        """Generate bcrypt hash for the given text"""
        if salt:
            return bcrypt.hashpw(text.encode(), salt).decode()
        else:
            return bcrypt.hashpw(text.encode(), bcrypt.gensalt()).decode()
    
    def _verify_bcrypt(self, text, hashed):
        """Verify a bcrypt hash"""
        try:
            return bcrypt.checkpw(text.encode(), hashed.encode())
        except Exception:
            return False
    
    def identify_hash_type(self, hash_value):
        """Attempt to identify the hash type based on characteristics"""
        hash_length = len(hash_value)
        
        if hash_length == 32 and all(c in string.hexdigits for c in hash_value):
            return 'md5'
        elif hash_length == 40 and all(c in string.hexdigits for c in hash_value):
            return 'sha1'
        elif hash_length == 64 and all(c in string.hexdigits for c in hash_value):
            return 'sha256'
        elif hash_length == 128 and all(c in string.hexdigits for c in hash_value):
            return 'sha512'
        elif hash_value.startswith('$2a$') or hash_value.startswith('$2b$') or hash_value.startswith('$2y$'):
            return 'bcrypt'
        else:
            return None
    
    def dictionary_attack(self, hash_value, hash_type, wordlist_path, encoding='utf-8'):
        """
        Perform a dictionary attack using the specified wordlist
        """
        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
        
        self.statistics['start_time'] = time.time()
        self.statistics['method_used'] = 'dictionary_attack'
        
        # Get file size for progress bar
        file_size = os.path.getsize(wordlist_path)
        
        try:
            with open(wordlist_path, 'r', encoding=encoding, errors='ignore') as f:
                wordlist = tqdm(f, total=file_size, unit='B', unit_scale=True, desc=f"{Fore.CYAN}Dictionary attack")
                
                for word in wordlist:
                    word = word.strip()
                    self.statistics['attempts'] += 1
                    
                    # Handle bcrypt differently
                    if hash_type == 'bcrypt':
                        if self._verify_bcrypt(word, hash_value):
                            self.statistics['end_time'] = time.time()
                            self.statistics['success'] = True
                            self._save_result(hash_value, hash_type, word)
                            return word
                    else:
                        # For other hash types
                        hash_function = self.supported_algorithms.get(hash_type)
                        if hash_function(word) == hash_value.lower():
                            self.statistics['end_time'] = time.time()
                            self.statistics['success'] = True
                            self._save_result(hash_value, hash_type, word)
                            return word
        except UnicodeDecodeError:
            logger.warning(f"Encoding issue with wordlist. Trying with 'latin-1' encoding.")
            return self.dictionary_attack(hash_value, hash_type, wordlist_path, encoding='latin-1')
        
        self.statistics['end_time'] = time.time()
        return None
    
    def _process_chunk(self, args):
        """Process a chunk of brute force candidates (for multiprocessing)"""
        chunk, hash_value, hash_type = args
        results = []
        
        for candidate in chunk:
            if hash_type == 'bcrypt':
                if self._verify_bcrypt(candidate, hash_value):
                    results.append(candidate)
            else:
                hash_function = self.supported_algorithms.get(hash_type)
                if hash_function(candidate) == hash_value.lower():
                    results.append(candidate)
        
        return results
    
    def brute_force(self, hash_value, hash_type, charset=None, min_length=1, max_length=8, num_processes=None):
        """
        Perform a brute force attack for the given hash
        """
        if charset is None:
            charset = self.config['default_charset']
        
        if num_processes is None:
            num_processes = self.config['max_processes']
        
        self.statistics['start_time'] = time.time()
        self.statistics['method_used'] = 'brute_force'
        
        logger.info(f"Starting brute force attack with {num_processes} processes")
        logger.info(f"Character set: {charset}")
        logger.info(f"Length range: {min_length} to {max_length}")
        
        found = False
        result = None
        
        with multiprocessing.Pool(processes=num_processes) as pool:
            for length in range(min_length, max_length + 1):
                if found:
                    break
                
                logger.info(f"Trying length {length}...")
                total_combinations = len(charset) ** length
                
                if total_combinations > 1000000000:  # Over a billion combinations
                    logger.warning(f"Warning: Length {length} has {total_combinations} combinations")
                    user_input = input("Continue with this length? (y/n): ")
                    if user_input.lower() != 'y':
                        continue
                
                # Create chunks for multiprocessing
                all_candidates = (''.join(candidate) for candidate in itertools.product(charset, repeat=length))
                chunk_size = 10000  # Adjust based on memory constraints
                
                chunks = []
                temp_chunk = []
                
                # Create progress bar for this length
                pbar = tqdm(total=total_combinations, desc=f"{Fore.CYAN}Length {length}", unit="combinations")
                
                for idx, candidate in enumerate(all_candidates):
                    temp_chunk.append(candidate)
                    self.statistics['attempts'] += 1
                    
                    if len(temp_chunk) >= chunk_size:
                        chunks.append((temp_chunk.copy(), hash_value, hash_type))
                        temp_chunk = []
                        
                        # Process this batch
                        for batch_result in pool.imap_unordered(self._process_chunk, chunks):
                            if batch_result:
                                result = batch_result[0]
                                found = True
                                break
                            pbar.update(chunk_size * len(chunks))
                        
                        if found:
                            break
                        
                        chunks = []
                
                # Process any remaining candidates
                if temp_chunk and not found:
                    chunks.append((temp_chunk, hash_value, hash_type))
                    for batch_result in pool.imap_unordered(self._process_chunk, chunks):
                        if batch_result:
                            result = batch_result[0]
                            found = True
                            break
                        pbar.update(len(temp_chunk))
                
                pbar.close()
                
                if found:
                    break
        
        self.statistics['end_time'] = time.time()
        
        if result:
            self.statistics['success'] = True
            self._save_result(hash_value, hash_type, result)
        
        return result
    
    def _save_result(self, hash_value, hash_type, plaintext):
        """Save the successful result to a file"""
        if not self.config.get('save_results', True):
            return
        
        results_file = self.config.get('results_file', 'hash_results.json')
        
        # Create the results directory if it doesn't exist
        results_dir = os.path.dirname(results_file)
        if results_dir and not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        result_data = {
            'hash': hash_value,
            'type': hash_type,
            'plaintext': plaintext,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'statistics': {
                'duration': self.statistics['end_time'] - self.statistics['start_time'],
                'attempts': self.statistics['attempts'],
                'method': self.statistics['method_used']
            }
        }
        
        # Load existing results if the file exists
        existing_results = []
        if os.path.exists(results_file):
            try:
                with open(results_file, 'r') as f:
                    existing_results = json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Error parsing results file. Creating new file.")
        
        # Add the new result
        existing_results.append(result_data)
        
        # Save the updated results
        with open(results_file, 'w') as f:
            json.dump(existing_results, f, indent=2)
    
    def hybrid_attack(self, hash_value, hash_type, wordlist_path, rules=None):
        """
        Perform a hybrid attack combining dictionary words with transformations
        """
        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
        
        self.statistics['start_time'] = time.time()
        self.statistics['method_used'] = 'hybrid_attack'
        
        default_rules = [
            lambda w: w,                      # Original word
            lambda w: w.capitalize(),         # Capitalize
            lambda w: w.upper(),              # ALL CAPS
            lambda w: w.lower(),              # lowercase
            lambda w: w + "123",              # Append common numbers
            lambda w: w + "!",                # Append !
            lambda w: w + "@",                # Append @
            lambda w: "123" + w,              # Prepend common numbers
            lambda w: w.replace('a', '@'),    # Letter substitution
            lambda w: w.replace('e', '3'),    # Letter substitution
            lambda w: w.replace('i', '1'),    # Letter substitution
            lambda w: w.replace('o', '0'),    # Letter substitution
            lambda w: w + "2023",             # Append year
            lambda w: w + "2024",             # Append year
            lambda w: w + "2025",             # Append year
        ]
        
        if rules is None:
            rules = default_rules
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                total_size = os.path.getsize(wordlist_path)
                wordlist = tqdm(f, total=total_size, unit='B', unit_scale=True, desc=f"{Fore.CYAN}Hybrid attack")
                
                for line in wordlist:
                    word = line.strip()
                    if not word:
                        continue
                    
                    # Apply each rule to the word
                    for rule in rules:
                        try:
                            transformed_word = rule(word)
                            self.statistics['attempts'] += 1
                            
                            # Handle bcrypt differently
                            if hash_type == 'bcrypt':
                                if self._verify_bcrypt(transformed_word, hash_value):
                                    self.statistics['end_time'] = time.time()
                                    self.statistics['success'] = True
                                    self._save_result(hash_value, hash_type, transformed_word)
                                    return transformed_word
                            else:
                                # For other hash types
                                hash_function = self.supported_algorithms.get(hash_type)
                                if hash_function(transformed_word) == hash_value.lower():
                                    self.statistics['end_time'] = time.time()
                                    self.statistics['success'] = True
                                    self._save_result(hash_value, hash_type, transformed_word)
                                    return transformed_word
                        except Exception as e:
                            # Skip if rule application fails
                            continue
        except UnicodeDecodeError:
            logger.warning(f"Encoding issue with wordlist. Trying with 'latin-1' encoding.")
            return self.hybrid_attack(hash_value, hash_type, wordlist_path, rules)
        
        self.statistics['end_time'] = time.time()
        return None
    
    def analyze_hash(self, hash_value, hash_type=None, methods=None, wordlist=None):
        """
        Main method to analyze a hash using various methods
        """
        if hash_type is None:
            detected_type = self.identify_hash_type(hash_value)
            if detected_type:
                logger.info(f"Detected hash type: {detected_type}")
                hash_type = detected_type
            else:
                logger.error("Could not identify hash type. Please specify the type.")
                return None
        
        if hash_type not in self.supported_algorithms:
            logger.error(f"Unsupported hash type: {hash_type}")
            logger.info(f"Supported types: {', '.join(self.supported_algorithms.keys())}")
            return None
        
        if wordlist is None:
            wordlist = self.config['default_wordlist']
        
        if methods is None:
            methods = ['dictionary', 'hybrid', 'brute_force']
        
        result = None
        
        for method in methods:
            if result:
                break
            
            if method == 'dictionary':
                logger.info(f"Attempting dictionary attack with wordlist: {wordlist}")
                result = self.dictionary_attack(hash_value, hash_type, wordlist)
                if result:
                    logger.info(f"{Fore.GREEN}Password found: {result}")
                else:
                    logger.info(f"{Fore.YELLOW}Dictionary attack unsuccessful")
            
            elif method == 'hybrid':
                logger.info(f"Attempting hybrid attack with wordlist: {wordlist}")
                result = self.hybrid_attack(hash_value, hash_type, wordlist)
                if result:
                    logger.info(f"{Fore.GREEN}Password found: {result}")
                else:
                    logger.info(f"{Fore.YELLOW}Hybrid attack unsuccessful")
            
            elif method == 'brute_force':
                max_length = self.config['max_brute_force_length']
                logger.info(f"Attempting brute force attack (up to {max_length} chars)")
                result = self.brute_force(hash_value, hash_type, max_length=max_length)
                if result:
                    logger.info(f"{Fore.GREEN}Password found: {result}")
                else:
                    logger.info(f"{Fore.YELLOW}Brute force attack unsuccessful")
        
        # Print statistics
        if self.statistics['end_time'] and self.statistics['start_time']:
            duration = self.statistics['end_time'] - self.statistics['start_time']
            logger.info(f"Analysis completed in {duration:.2f} seconds")
            logger.info(f"Total attempts: {self.statistics['attempts']}")
            logger.info(f"Method: {self.statistics['method_used']}")
        
        return result


def main():
    parser = argparse.ArgumentParser(description='HashAnalyzer - A hash analysis tool')
    parser.add_argument('hash', help='The hash to analyze')
    parser.add_argument('--type', choices=['md5', 'sha1', 'sha256', 'sha512', 'bcrypt'], 
                        help='Hash type (autodetected if not specified)')
    parser.add_argument('--wordlist', help='Path to wordlist file')
    parser.add_argument('--methods', nargs='+', choices=['dictionary', 'hybrid', 'brute_force'], 
                        default=['dictionary', 'hybrid', 'brute_force'],
                        help='Methods to use in order (default: all)')
    parser.add_argument('--max-length', type=int, help='Maximum length for brute force')
    parser.add_argument('--charset', help='Character set for brute force')
    parser.add_argument('--processes', type=int, help='Number of processes for brute force')
    
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}╔═══════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║         HashAnalyzer Tool v1.0            ║")
    print(f"{Fore.CYAN}║      For Educational Purposes Only        ║")
    print(f"{Fore.CYAN}╚═══════════════════════════════════════════╝")
    
    analyzer = HashAnalyzer()
    
    if args.max_length:
        analyzer.config['max_brute_force_length'] = args.max_length
    
    if args.charset:
        analyzer.config['default_charset'] = args.charset
    
    if args.processes:
        analyzer.config['max_processes'] = args.processes
    
    try:
        result = analyzer.analyze_hash(
            args.hash, 
            hash_type=args.type, 
            methods=args.methods,
            wordlist=args.wordlist
        )
        
        if result:
            print(f"\n{Fore.GREEN}[+] Match found: {Style.BRIGHT}{result}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[-] No match found for the given hash{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation cancelled by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
