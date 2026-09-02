"""
Entropy Calculation Module
Implements Shannon entropy and related features for domain analysis.
"""

import logging
import math
from typing import Dict, Any, List, Optional
from collections import Counter
import re

logger = logging.getLogger(__name__)


class EntropyCalculator:
    """Calculates entropy features for strings (domains, etc.)"""
    
    @staticmethod
    def shannon_entropy(text: str, base: int = 2) -> float:
        """
        Calculate Shannon entropy of a string
        
        Args:
            text: Input string
            base: Logarithm base (default: 2 for bits)
            
        Returns:
            Entropy value in bits (or nats if base=e)
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text)
        text_length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log(probability, base)
        
        return entropy
    
    @staticmethod
    def normalized_entropy(text: str) -> float:
        """
        Calculate normalized entropy (0-1 range)
        
        Args:
            text: Input string
            
        Returns:
            Normalized entropy between 0 and 1
        """
        if not text:
            return 0.0
        
        max_entropy = math.log(len(set(text)), 2) if len(set(text)) > 1 else 1.0
        if max_entropy == 0:
            return 0.0
        
        actual_entropy = EntropyCalculator.shannon_entropy(text)
        return actual_entropy / max_entropy
    
    @staticmethod
    def character_frequency_entropy(text: str) -> float:
        """
        Calculate entropy based on character frequency distribution
        
        Args:
            text: Input string
            
        Returns:
            Entropy value
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text.lower())
        total_chars = len(text)
        
        # Calculate frequency distribution entropy
        entropy = 0.0
        for count in char_counts.values():
            frequency = count / total_chars
            if frequency > 0:
                entropy -= frequency * math.log(frequency, 2)
        
        return entropy


class DomainEntropyAnalyzer:
    """Analyzes domain names for entropy and structure features"""
    
    def __init__(self):
        """Initialize domain analyzer"""
        self.common_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.io', '.co', '.uk'}
        logger.info("Initialized DomainEntropyAnalyzer")
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analyze a domain name for various features
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dictionary with domain features
        """
        if not domain:
            return self._empty_domain_features()
        
        # Clean domain (remove protocol, path, etc.)
        clean_domain = self._clean_domain(domain)
        
        # Split domain into labels
        labels = clean_domain.split('.')
        main_label = labels[0] if labels else ""
        tld = f".{labels[-1]}" if len(labels) > 1 else ""
        
        # Calculate features
        features = {
            "domain": clean_domain,
            "length": len(clean_domain),
            "main_label_length": len(main_label),
            "num_labels": len(labels),
            "entropy": self.calculate_domain_entropy(clean_domain),
            "normalized_entropy": EntropyCalculator.normalized_entropy(clean_domain),
            "digit_ratio": self.calculate_digit_ratio(clean_domain),
            "vowel_ratio": self.calculate_vowel_ratio(clean_domain),
            "consonant_ratio": self.calculate_consonant_ratio(clean_domain),
            "unique_chars": len(set(clean_domain)),
            "has_hyphen": '-' in clean_domain,
            "has_digits": any(c.isdigit() for c in clean_domain),
            "has_uppercase": any(c.isupper() for c in clean_domain),
            "tld": tld,
            "is_common_tld": tld in self.common_tlds
        }
        
        # Add n-gram features
        features.update(self.calculate_ngram_features(main_label))
        
        return features
    
    def calculate_domain_entropy(self, domain: str) -> float:
        """
        Calculate entropy for domain name
        
        Args:
            domain: Domain name
            
        Returns:
            Shannon entropy of domain
        """
        return EntropyCalculator.shannon_entropy(domain)
    
    @staticmethod
    def calculate_digit_ratio(text: str) -> float:
        """
        Calculate ratio of digits in string
        
        Args:
            text: Input string
            
        Returns:
            Ratio of digits (0-1)
        """
        if not text:
            return 0.0
        
        digits = sum(1 for c in text if c.isdigit())
        return digits / len(text)
    
    @staticmethod
    def calculate_vowel_ratio(text: str) -> float:
        """
        Calculate ratio of vowels in string
        
        Args:
            text: Input string
            
        Returns:
            Ratio of vowels (0-1)
        """
        if not text:
            return 0.0
        
        vowels = set('aeiou')
        vowel_count = sum(1 for c in text.lower() if c in vowels)
        return vowel_count / len(text)
    
    @staticmethod
    def calculate_consonant_ratio(text: str) -> float:
        """
        Calculate ratio of consonants in string
        
        Args:
            text: Input string
            
        Returns:
            Ratio of consonants (0-1)
        """
        if not text:
            return 0.0
        
        consonants = set('bcdfghjklmnpqrstvwxyz')
        consonant_count = sum(1 for c in text.lower() if c in consonants)
        return consonant_count / len(text)
    
    def calculate_ngram_features(self, text: str, n: int = 2) -> Dict[str, float]:
        """
        Calculate n-gram based features for text
        
        Args:
            text: Input string
            n: n-gram size
            
        Returns:
            Dictionary with n-gram features
        """
        if not text:
            return {"ngram_score": 0.0, "unique_ngrams": 0, "ngram_entropy": 0.0}
        
        # Common English bigrams/trigrams for reference
        common_ngrams = {
            'th', 'he', 'in', 'en', 'nt', 're', 'er', 'an', 'ti', 'es',
            'on', 'at', 'se', 'nd', 'or', 'ar', 'al', 'te', 'co', 'de'
        }
        
        # Generate n-grams
        ngrams = []
        for i in range(len(text) - n + 1):
            ngram = text[i:i+n].lower()
            ngrams.append(ngram)
        
        if not ngrams:
            # BUGFIX: previously omitted "ngram_entropy" here (only
            # present in the non-empty-ngrams branch below), giving this
            # function two inconsistent return shapes -- one WITH
            # ngram_entropy, one WITHOUT. Not observed to crash anywhere
            # currently (dga.py reads "ngram_score" via .get() with a
            # default), but text shorter than n (e.g. a short DGA-style
            # main label) is a realistic input here, and any future
            # caller doing features["ngram_entropy"] directly would
            # KeyError on exactly that input. Always return the same
            # keys.
            return {"ngram_score": 0.0, "unique_ngrams": 0, "ngram_entropy": 0.0}
        
        # Calculate n-gram frequency
        ngram_counts = Counter(ngrams)
        unique_ngrams = len(ngram_counts)
        
        # Calculate "commonness" score
        common_count = sum(1 for ng in ngrams if ng in common_ngrams)
        common_ratio = common_count / len(ngrams)
        
        # Calculate n-gram entropy
        ngram_entropy = EntropyCalculator.shannon_entropy(''.join(ngrams))
        
        return {
            "ngram_score": common_ratio,
            "unique_ngrams": unique_ngrams,
            "ngram_entropy": ngram_entropy
        }
    
    def _clean_domain(self, domain: str) -> str:
        """Clean domain name (remove protocol, path, etc.)"""
        # Remove protocol if present
        if '://' in domain:
            domain = domain.split('://')[1]
        
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/')[0]
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Convert to lowercase
        return domain.lower()
    
    def _empty_domain_features(self) -> Dict[str, Any]:
        """Return empty domain features"""
        return {
            "domain": "",
            "length": 0,
            "main_label_length": 0,
            "num_labels": 0,
            "entropy": 0.0,
            "normalized_entropy": 0.0,
            "digit_ratio": 0.0,
            "vowel_ratio": 0.0,
            "consonant_ratio": 0.0,
            "unique_chars": 0,
            "has_hyphen": False,
            "has_digits": False,
            "has_uppercase": False,
            "tld": "",
            "is_common_tld": False,
            "ngram_score": 0.0,
            "unique_ngrams": 0,
            "ngram_entropy": 0.0
        }