"""
SHA-256 Hash-Chain Audit Module
Implements a simple hash chain for alert integrity verification.
NOTE: This is NOT a blockchain - just a cryptographic hash chain.
"""

import logging
import hashlib
import os
import tempfile
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import uuid

logger = logging.getLogger(__name__)


@dataclass
class HashChainEntry:
    """Single entry in the hash chain"""
    index: int
    timestamp: str
    alert_id: str
    data_hash: str
    previous_hash: str
    current_hash: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


class HashChain:
    """SHA-256 hash chain for alert integrity"""
    
    def __init__(self, chain_file: Optional[str] = None):
        """
        Initialize hash chain
        
        Args:
            chain_file: Path to store chain data (optional)
        """
        self.chain: List[HashChainEntry] = []
        self.chain_file = chain_file
        
        if chain_file:
            self.chain_path = Path(chain_file)
            self.chain_path.parent.mkdir(parents=True, exist_ok=True)
            self._load_chain()
        
        logger.info(f"Initialized HashChain with {len(self.chain)} entries")
    
    def _load_chain(self):
        """Load chain from file if exists"""
        if not self.chain_path.exists():
            return
        
        try:
            with open(self.chain_path, 'r') as f:
                data = json.load(f)
                self.chain = [
                    HashChainEntry(**entry) for entry in data.get('chain', [])
                ]
            logger.info(f"Loaded {len(self.chain)} entries from {self.chain_path}")
        except Exception as e:
            logger.error(f"Failed to load chain: {e}")
            raise RuntimeError(f"Hash-chain state is unreadable: {self.chain_path}") from e
    
    def _save_chain(self):
        """Save chain to file"""
        if not self.chain_file:
            return
        
        try:
            data = {
                'chain': [entry.to_dict() for entry in self.chain],
                'total_entries': len(self.chain),
                'last_hash': self.get_last_hash(),
                'saved_at': datetime.now(timezone.utc).isoformat()
            }
            
            with open(self.chain_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Saved chain to {self.chain_path}")
        except Exception as e:
            logger.error(f"Failed to save chain: {e}")
    
    def calculate_hash(self, data: Any) -> str:
        """
        Calculate SHA-256 hash of data
        
        Args:
            data: Data to hash (will be converted to string)
            
        Returns:
            SHA-256 hash
        """
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, sort_keys=True, default=str)
        else:
            data_str = str(data)
        
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def create_alert_hash(self, alert: Any) -> str:
        """
        Create hash of alert data
        
        Args:
            alert: Alert object or dictionary
            
        Returns:
            SHA-256 hash of alert
        """
        if hasattr(alert, 'to_dict'):
            alert_data = alert.to_dict()
        elif isinstance(alert, dict):
            alert_data = alert
        else:
            alert_data = {'alert': str(alert)}
        
        return self.calculate_hash(alert_data)
    
    def append_alert(self, alert: Any) -> Optional[HashChainEntry]:
        """
        Append alert to hash chain
        
        Args:
            alert: Alert to add to chain
            
        Returns:
            HashChainEntry or None if failed
        """
        try:
            # Get alert ID
            alert_id = getattr(alert, 'alert_id', None) or alert.get('alert_id', str(uuid.uuid4()))
            
            # Calculate alert hash
            alert_hash = self.create_alert_hash(alert)
            
            # Get previous hash
            previous_hash = self.get_last_hash() or "0" * 64  # Genesis block
            
            # Create entry data
            index = len(self.chain)
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Calculate current hash
            entry_data = {
                'index': index,
                'timestamp': timestamp,
                'alert_id': alert_id,
                'data_hash': alert_hash,
                'previous_hash': previous_hash
            }
            current_hash = self.calculate_hash(entry_data)
            
            # Create entry
            entry = HashChainEntry(
                index=index,
                timestamp=timestamp,
                alert_id=alert_id,
                data_hash=alert_hash,
                previous_hash=previous_hash,
                current_hash=current_hash
            )
            
            # Add to chain
            self.chain.append(entry)
            
            # Save to file
            self._save_chain()
            
            logger.info(f"Appended alert {alert_id} to chain at index {index}")
            return entry
            
        except Exception as e:
            logger.error(f"Failed to append alert: {e}")
            raise RuntimeError("Hash-chain append was not durably persisted") from e
    
    def append_alerts(self, alerts: List[Any]) -> int:
        """
        Append multiple alerts to chain
        
        Args:
            alerts: List of alerts
            
        Returns:
            Number of alerts appended
        """
        count = 0
        for alert in alerts:
            if self.append_alert(alert):
                count += 1
        
        logger.info(f"Appended {count} alerts to chain")
        return count
    
    def get_last_hash(self) -> Optional[str]:
        """Get hash of last entry"""
        if self.chain:
            return self.chain[-1].current_hash
        return None
    
    def get_chain(self) -> List[HashChainEntry]:
        """Get full chain"""
        return self.chain.copy()
    
    def get_entry(self, index: int) -> Optional[HashChainEntry]:
        """Get entry by index"""
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None
    
    def get_entry_by_alert_id(self, alert_id: str) -> Optional[HashChainEntry]:
        """Get entry by alert ID"""
        for entry in self.chain:
            if entry.alert_id == alert_id:
                return entry
        return None
    
    def validate_chain(self) -> Dict[str, Any]:
        """
        Validate integrity of entire chain
        
        Returns:
            Dictionary with validation results
        """
        validation_result = {
            'is_valid': True,
            'total_entries': len(self.chain),
            'valid_entries': 0,
            'invalid_entries': [],
            'errors': []
        }
        
        for i, entry in enumerate(self.chain):
            # Verify index
            if entry.index != i:
                validation_result['is_valid'] = False
                validation_result['invalid_entries'].append(i)
                validation_result['errors'].append(f"Entry {i}: Invalid index")
                continue
            
            # Verify previous hash
            if i > 0:
                expected_previous = self.chain[i - 1].current_hash
                if entry.previous_hash != expected_previous:
                    validation_result['is_valid'] = False
                    validation_result['invalid_entries'].append(i)
                    validation_result['errors'].append(
                        f"Entry {i}: Previous hash mismatch"
                    )
                    continue
            
            # Verify current hash
            entry_data = {
                'index': entry.index,
                'timestamp': entry.timestamp,
                'alert_id': entry.alert_id,
                'data_hash': entry.data_hash,
                'previous_hash': entry.previous_hash
            }
            calculated_hash = self.calculate_hash(entry_data)
            
            if entry.current_hash != calculated_hash:
                validation_result['is_valid'] = False
                validation_result['invalid_entries'].append(i)
                validation_result['errors'].append(
                    f"Entry {i}: Current hash mismatch"
                )
            else:
                validation_result['valid_entries'] += 1
        
        validation_result['valid_entries'] = len(self.chain) - len(validation_result['invalid_entries'])
        
        logger.info(f"Chain validation: {'valid' if validation_result['is_valid'] else 'invalid'}")
        return validation_result
    
    def validate_alert(self, alert: Any) -> Dict[str, Any]:
        """
        Validate a single alert against chain
        
        Args:
            alert: Alert to validate
            
        Returns:
            Dictionary with validation result
        """
        alert_id = getattr(alert, 'alert_id', None) or alert.get('alert_id', None)
        
        if not alert_id:
            return {
                'is_valid': False,
                'error': 'Alert has no ID'
            }
        
        entry = self.get_entry_by_alert_id(alert_id)
        
        if not entry:
            return {
                'is_valid': False,
                'error': f'Alert {alert_id} not found in chain'
            }
        
        # Calculate current hash of alert
        current_alert_hash = self.create_alert_hash(alert)
        
        # Compare with stored hash
        if current_alert_hash != entry.data_hash:
            return {
                'is_valid': False,
                'error': 'Alert data has been modified',
                'alert_id': alert_id,
                'original_hash': entry.data_hash,
                'current_hash': current_alert_hash
            }
        
        return {
            'is_valid': True,
            'alert_id': alert_id,
            'hash': entry.data_hash,
            'entry_index': entry.index
        }
    
    def detect_tampering(self, modified_alert: Any) -> Dict[str, Any]:
        """
        Detect if an alert has been tampered with
        
        Args:
            modified_alert: Alert that may have been modified
            
        Returns:
            Dictionary with tampering detection result
        """
        result = self.validate_alert(modified_alert)
        
        if not result['is_valid']:
            result['tampering_detected'] = True
        else:
            result['tampering_detected'] = False
        
        return result
    
    def get_chain_statistics(self) -> Dict[str, Any]:
        """Get chain statistics"""
        return {
            'total_entries': len(self.chain),
            'first_entry_time': self.chain[0].timestamp if self.chain else None,
            'last_entry_time': self.chain[-1].timestamp if self.chain else None,
            'last_hash': self.get_last_hash(),
            'chain_file': self.chain_file
        }
    
    def export_chain(self, filepath: str) -> bool:
        """
        Export chain to JSON file
        
        Args:
            filepath: Path to export file
            
        Returns:
            True if successful
        """
        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                'chain': [entry.to_dict() for entry in self.chain],
                'total_entries': len(self.chain),
                'exported_at': datetime.now(timezone.utc).isoformat()
            }
            
            with open(path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Exported chain to {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export chain: {e}")
            return False
    
    def clear_chain(self):
        """Clear all entries from chain"""
        self.chain.clear()
        if self.chain_file:
            self._save_chain()
        logger.info("Chain cleared")