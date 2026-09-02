"""
Database Module
SQLite database for storing alerts and flow statistics.
Uses SQLAlchemy ORM for database operations.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

from sqlalchemy import (
    create_engine, text, 
    Column, 
    Integer, 
    String, 
    Float, 
    DateTime, 
    Text, 
    Boolean, 
    ForeignKey, 
    Index,
    func
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from sqlalchemy.exc import SQLAlchemyError

from src.alerts.alert_models import Alert

logger = logging.getLogger(__name__)

def _json_default(value: Any):
    """Convert common NumPy/scientific scalar values to native JSON types."""
    if hasattr(value, "item"):
        return value.item()
    if hasattr(value, "tolist"):
        return value.tolist()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (datetime,)):
        return value.astimezone(timezone.utc).isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def serialize_alert(alert: Alert) -> str:
    """Canonical deterministic JSON representation for audit/storage."""
    return json.dumps(
        alert.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )

# Create declarative base
Base = declarative_base()


class AlertRecord(Base):
    """SQLAlchemy model for alert storage"""
    __tablename__ = 'alerts'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(100), unique=True, nullable=False, index=True)
    
    # Alert information
    timestamp = Column(DateTime, nullable=False, index=True)
    threat_type = Column(String(50), nullable=False, index=True)
    category = Column(String(50), index=True)
    severity = Column(String(20), nullable=False, index=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    confidence = Column(Float, nullable=False, default=0.0)
    event_time = Column(String(64), nullable=True, index=True)
    processing_time = Column(String(64), nullable=True)
    flow_id = Column(String(100), nullable=True, index=True)
    window_id = Column(Integer, nullable=True, index=True)
    attack_type = Column(String(100), nullable=True)
    attack_subtype = Column(String(100), nullable=True)
    rule_score = Column(Float, nullable=True)
    rule_confidence = Column(Float, nullable=True)
    decision_confidence = Column(Float, nullable=True)
    ml_probability = Column(Float, nullable=True)
    ml_label = Column(String(100), nullable=True)
    ml_anomaly_score = Column(Float, nullable=True)
    ml_model_version = Column(String(100), nullable=True)
    cti_score = Column(Float, nullable=True)
    incident_id = Column(String(100), nullable=True, index=True)
    observation_quality = Column(String(20), nullable=False, default="GOOD")
    degradation_reasons_json = Column(Text, nullable=True)
    cti_status = Column(String(30), nullable=True)
    schema_version = Column(String(50), nullable=True)
    risk_breakdown_json = Column(Text, nullable=True)
    
    # Network information
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    
    # Detection information
    detector = Column(String(50), index=True)
    status = Column(String(20), default='NEW', index=True)
    
    # Details
    description = Column(Text)
    details_json = Column(Text)  # JSON string for details
    evidence_json = Column(Text)  # JSON string for evidence
    
    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'threat_type': self.threat_type,
            'category': self.category,
            'severity': self.severity,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'event_time': self.event_time,
            'processing_time': self.processing_time,
            'flow_id': self.flow_id,
            'window_id': self.window_id,
            'attack_type': self.attack_type,
            'attack_subtype': self.attack_subtype,
            'rule_score': self.rule_score,
            'rule_confidence': self.rule_confidence,
            'decision_confidence': self.decision_confidence,
            'ml_probability': self.ml_probability,
            'ml_label': self.ml_label,
            'ml_anomaly_score': self.ml_anomaly_score,
            'ml_model_version': self.ml_model_version,
            'cti_score': self.cti_score,
            'incident_id': self.incident_id,
            'observation_quality': self.observation_quality,
            'degradation_reasons': json.loads(self.degradation_reasons_json) if self.degradation_reasons_json else [],
            'cti_status': self.cti_status,
            'schema_version': self.schema_version,
            'risk_breakdown': json.loads(self.risk_breakdown_json) if self.risk_breakdown_json else [],
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'detector': self.detector,
            'status': self.status,
            'description': self.description,
            'details': json.loads(self.details_json) if self.details_json else {},
            'evidence': json.loads(self.evidence_json) if self.evidence_json else {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def to_alert(self) -> Alert:
        """Convert to Alert object"""
        return Alert(
            alert_id=self.alert_id,
            timestamp=self.timestamp.isoformat() if self.timestamp else None,
            threat_type=self.threat_type,
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            severity=self.severity,
            risk_score=self.risk_score,
            confidence=self.confidence,
            event_time=self.event_time,
            processing_time=self.processing_time,
            flow_id=self.flow_id,
            window_id=self.window_id,
            attack_type=self.attack_type,
            attack_subtype=self.attack_subtype,
            rule_score=self.rule_score,
            rule_confidence=self.rule_confidence,
            decision_confidence=self.decision_confidence or 0.0,
            ml_probability=self.ml_probability,
            ml_label=self.ml_label,
            ml_anomaly_score=self.ml_anomaly_score,
            ml_model_version=self.ml_model_version,
            cti_score=self.cti_score,
            incident_id=self.incident_id,
            observation_quality=self.observation_quality,
            degradation_reasons=json.loads(self.degradation_reasons_json) if self.degradation_reasons_json else [],
            cti_status=self.cti_status,
            schema_version=self.schema_version or "alert-v2",
            risk_breakdown=json.loads(self.risk_breakdown_json) if self.risk_breakdown_json else [],
            detector=self.detector,
            description=self.description or '',
            details=json.loads(self.details_json) if self.details_json else {},
            evidence=json.loads(self.evidence_json) if self.evidence_json else {},
            status=self.status,
            category=self.category
        )
    
    @classmethod
    def from_alert(cls, alert: Alert) -> 'AlertRecord':
        """Create AlertRecord from Alert object"""
        # Parse timestamp
        if alert.timestamp:
            try:
                if isinstance(alert.timestamp, str):
                    timestamp = datetime.fromisoformat(alert.timestamp)
                elif isinstance(alert.timestamp, datetime):
                    timestamp = alert.timestamp
                else:
                    timestamp = datetime.now(timezone.utc)
            except (TypeError, ValueError):
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)
        
        return cls(
            alert_id=alert.alert_id,
            timestamp=timestamp,
            threat_type=alert.threat_type,
            category=alert.category,
            severity=alert.severity,
            risk_score=alert.risk_score,
            confidence=alert.confidence,
            event_time=alert.event_time,
            processing_time=alert.processing_time,
            flow_id=alert.flow_id,
            window_id=alert.window_id,
            attack_type=alert.attack_type,
            attack_subtype=alert.attack_subtype,
            rule_score=alert.rule_score,
            rule_confidence=alert.rule_confidence,
            decision_confidence=alert.decision_confidence,
            ml_probability=alert.ml_probability,
            ml_label=alert.ml_label,
            ml_anomaly_score=alert.ml_anomaly_score,
            ml_model_version=alert.ml_model_version,
            cti_score=alert.cti_score,
            incident_id=alert.incident_id,
            observation_quality=alert.observation_quality,
            degradation_reasons_json=json.dumps(alert.degradation_reasons or [], sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=_json_default),
            cti_status=alert.cti_status,
            schema_version=alert.schema_version,
            risk_breakdown_json=json.dumps(alert.risk_breakdown or [], sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=_json_default),
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            detector=alert.detector,
            status=alert.status,
            description=alert.description,
            details_json=json.dumps(alert.details or {}, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=_json_default),
            evidence_json=json.dumps(alert.evidence or {}, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=_json_default)
        )


class FlowStatisticsRecord(Base):
    """SQLAlchemy model for flow statistics"""
    __tablename__ = 'flow_statistics'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    total_flows = Column(Integer, default=0)
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    unique_sources = Column(Integer, default=0)
    unique_destinations = Column(Integer, default=0)
    
    # JSON for additional statistics
    stats_json = Column(Text)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = {
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'total_flows': self.total_flows,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'unique_sources': self.unique_sources,
            'unique_destinations': self.unique_destinations
        }
        
        if self.stats_json:
            try:
                data.update(json.loads(self.stats_json))
            except (TypeError, ValueError):
                pass
        
        return data


class DatabaseManager:
    """Manages database operations"""
    
    def __init__(self, db_path: str = "data/threats.db", echo: bool = False):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file
            echo: Enable SQL echo for debugging
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create database engine
        self.engine = create_engine(
            f'sqlite:///{self.db_path}',
            echo=echo,
            connect_args={'check_same_thread': False, 'timeout': 30},
        )
        from sqlalchemy import event
        @event.listens_for(self.engine, "connect")
        def _configure_sqlite(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()
        
        # Create session factory
        self.Session = sessionmaker(bind=self.engine)
        
        # Initialize database
        self.init_database()
        
        logger.info(f"Initialized DatabaseManager with {self.db_path}")
    
    def init_database(self):
        """Initialize database schema"""
        try:
            Base.metadata.create_all(self.engine)
            self._migrate_schema()
            logger.info("Database schema initialized")
        except SQLAlchemyError as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def get_session(self) -> Session:
        """Get a new database session"""
        return self.Session()
    
    def health_check(self) -> bool:
        """Verify that the database is reachable."""
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except SQLAlchemyError as exc:
            logger.error("Database health check failed: %s", exc)
            return False

    def _migrate_schema(self) -> None:
        """Apply additive SQLite migrations for evolving alert evidence fields."""
        required = {
            "event_time": "VARCHAR(64)",
            "processing_time": "VARCHAR(64)",
            "flow_id": "VARCHAR(100)",
            "window_id": "INTEGER",
            "attack_type": "VARCHAR(100)",
            "attack_subtype": "VARCHAR(100)",
            "rule_score": "FLOAT",
            "rule_confidence": "FLOAT",
            "ml_probability": "FLOAT",
            "ml_label": "VARCHAR(100)",
            "ml_anomaly_score": "FLOAT",
            "ml_model_version": "VARCHAR(100)",
            "cti_score": "FLOAT",
            "risk_breakdown_json": "TEXT",
            "decision_confidence": "FLOAT",
            "incident_id": "VARCHAR(100)",
            "observation_quality": "VARCHAR(20)",
            "degradation_reasons_json": "TEXT",
            "cti_status": "VARCHAR(30)",
            "schema_version": "VARCHAR(50)",
        }
        with self.engine.begin() as conn:
            existing = {
                row[1]
                for row in conn.execute(text("PRAGMA table_info(alerts)")).fetchall()
            }
            for name, sql_type in required.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {name} {sql_type}"))
        logger.info("Database schema migration check complete")

    def serialize_for_audit(self, alert: Alert) -> str:
        return serialize_alert(alert)

    def add_alert(self, alert: Alert) -> bool:
        """
        Add an alert to the database
        
        Args:
            alert: Alert object to store
            
        Returns:
            True if successful, False otherwise
        """
        session = self.get_session()
        try:
            alert_record = AlertRecord.from_alert(alert)
            session.add(alert_record)
            session.commit()
            logger.debug(f"Added alert {alert.alert_id} to database")
            return True
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to add alert: {e}")
            return False
        finally:
            session.close()
    
    def add_alerts(self, alerts: List[Alert]) -> int:
        """Atomically add alerts; repeated alert IDs are idempotent."""
        if not alerts:
            return 0
        session = self.get_session()
        added_count = 0
        try:
            ids = [alert.alert_id for alert in alerts]
            existing = {row[0] for row in session.query(AlertRecord.alert_id).filter(
                AlertRecord.alert_id.in_(ids)
            ).all()}
            for alert in alerts:
                if alert.alert_id in existing:
                    continue
                session.add(AlertRecord.from_alert(alert))
                existing.add(alert.alert_id)
                added_count += 1
            session.commit()
            return added_count
        except SQLAlchemyError as exc:
            session.rollback()
            logger.error("Failed to add alerts atomically: %s", exc)
            return 0
        finally:
            session.close()

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """
        Get alert by ID
        
        Args:
            alert_id: Alert ID
            
        Returns:
            Alert object or None
        """
        session = self.get_session()
        try:
            record = session.query(AlertRecord).filter_by(alert_id=alert_id).first()
            return record.to_alert() if record else None
        except SQLAlchemyError as e:
            logger.error(f"Failed to get alert: {e}")
            return None
        finally:
            session.close()
    
    def get_alerts(self, limit: int = 100, offset: int = 0) -> List[Alert]:
        """
        Get recent alerts
        
        Args:
            limit: Maximum number of alerts to return
            offset: Offset for pagination
            
        Returns:
            List of Alert objects
        """
        session = self.get_session()
        try:
            records = session.query(AlertRecord)\
                .order_by(AlertRecord.timestamp.desc())\
                .limit(limit)\
                .offset(offset)\
                .all()
            
            return [record.to_alert() for record in records]
        except SQLAlchemyError as e:
            logger.error(f"Failed to get alerts: {e}")
            return []
        finally:
            session.close()
    
    def get_recent_alerts(self, hours: int = 24, limit: int = 100) -> List[Alert]:
        """
        Get alerts from recent time period
        
        Args:
            hours: Number of hours to look back
            limit: Maximum number of alerts
            
        Returns:
            List of Alert objects
        """
        session = self.get_session()
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            
            records = session.query(AlertRecord)\
                .filter(AlertRecord.timestamp >= cutoff_time)\
                .order_by(AlertRecord.timestamp.desc())\
                .limit(limit)\
                .all()
            
            return [record.to_alert() for record in records]
        except SQLAlchemyError as e:
            logger.error(f"Failed to get recent alerts: {e}")
            return []
        finally:
            session.close()
    
    def get_alerts_by_severity(self, severity: str, limit: int = 100) -> List[Alert]:
        """
        Get alerts by severity
        
        Args:
            severity: Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
            limit: Maximum number of alerts
            
        Returns:
            List of Alert objects
        """
        session = self.get_session()
        try:
            records = session.query(AlertRecord)\
                .filter_by(severity=severity)\
                .order_by(AlertRecord.timestamp.desc())\
                .limit(limit)\
                .all()
            
            return [record.to_alert() for record in records]
        except SQLAlchemyError as e:
            logger.error(f"Failed to get alerts by severity: {e}")
            return []
        finally:
            session.close()
    
    def get_alerts_by_type(self, threat_type: str, limit: int = 100) -> List[Alert]:
        """
        Get alerts by threat type
        
        Args:
            threat_type: Threat type
            limit: Maximum number of alerts
            
        Returns:
            List of Alert objects
        """
        session = self.get_session()
        try:
            records = session.query(AlertRecord)\
                .filter_by(threat_type=threat_type)\
                .order_by(AlertRecord.timestamp.desc())\
                .limit(limit)\
                .all()
            
            return [record.to_alert() for record in records]
        except SQLAlchemyError as e:
            logger.error(f"Failed to get alerts by type: {e}")
            return []
        finally:
            session.close()
    
    def get_alerts_by_source(self, source_ip: str, limit: int = 100) -> List[Alert]:
        """
        Get alerts by source IP
        
        Args:
            source_ip: Source IP address
            limit: Maximum number of alerts
            
        Returns:
            List of Alert objects
        """
        session = self.get_session()
        try:
            records = session.query(AlertRecord)\
                .filter_by(source_ip=source_ip)\
                .order_by(AlertRecord.timestamp.desc())\
                .limit(limit)\
                .all()
            
            return [record.to_alert() for record in records]
        except SQLAlchemyError as e:
            logger.error(f"Failed to get alerts by source: {e}")
            return []
        finally:
            session.close()
    
    def get_alerts_by_destination(self, destination_ip: str, limit: int = 100) -> List[Alert]:
        """
        Get alerts by destination IP
        
        Args:
            destination_ip: Destination IP address
            limit: Maximum number of alerts
            
        Returns:
            List of Alert objects
        """
        session = self.get_session()
        try:
            records = session.query(AlertRecord)\
                .filter_by(destination_ip=destination_ip)\
                .order_by(AlertRecord.timestamp.desc())\
                .limit(limit)\
                .all()
            
            return [record.to_alert() for record in records]
        except SQLAlchemyError as e:
            logger.error(f"Failed to get alerts by destination: {e}")
            return []
        finally:
            session.close()
    
    def update_alert_status(self, alert_id: str, new_status: str) -> bool:
        """
        Update alert status
        
        Args:
            alert_id: Alert ID
            new_status: New status (NEW, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE)
            
        Returns:
            True if successful
        """
        session = self.get_session()
        try:
            record = session.query(AlertRecord).filter_by(alert_id=alert_id).first()
            if record:
                record.status = new_status
                record.updated_at = datetime.now(timezone.utc)
                session.commit()
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to update alert status: {e}")
            return False
        finally:
            session.close()
    
    def delete_alert(self, alert_id: str) -> bool:
        """
        Delete alert by ID
        
        Args:
            alert_id: Alert ID
            
        Returns:
            True if successful
        """
        session = self.get_session()
        try:
            record = session.query(AlertRecord).filter_by(alert_id=alert_id).first()
            if record:
                session.delete(record)
                session.commit()
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to delete alert: {e}")
            return False
        finally:
            session.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get alert statistics
        
        Returns:
            Dictionary with statistics
        """
        session = self.get_session()
        try:
            stats = {
                'total_alerts': 0,
                'by_severity': {},
                'by_type': {},
                'by_status': {},
                'by_source': {},
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'average_risk_score': 0,
                'average_confidence': 0
            }
            
            # Total alerts
            stats['total_alerts'] = session.query(AlertRecord).count()
            
            if stats['total_alerts'] == 0:
                return stats
            
            # By severity
            severity_counts = session.query(
                AlertRecord.severity,
                func.count(AlertRecord.id)
            ).group_by(AlertRecord.severity).all()
            
            for severity, count in severity_counts:
                stats['by_severity'][severity] = count
                
                if severity == 'CRITICAL':
                    stats['critical_count'] = count
                elif severity == 'HIGH':
                    stats['high_count'] = count
                elif severity == 'MEDIUM':
                    stats['medium_count'] = count
                elif severity == 'LOW':
                    stats['low_count'] = count
            
            # By type
            type_counts = session.query(
                AlertRecord.threat_type,
                func.count(AlertRecord.id)
            ).group_by(AlertRecord.threat_type).all()
            
            for threat_type, count in type_counts:
                stats['by_type'][threat_type] = count
            
            # By status
            status_counts = session.query(
                AlertRecord.status,
                func.count(AlertRecord.id)
            ).group_by(AlertRecord.status).all()
            
            for status, count in status_counts:
                stats['by_status'][status] = count
            
            # By source (top 10)
            source_counts = session.query(
                AlertRecord.source_ip,
                func.count(AlertRecord.id)
            ).group_by(AlertRecord.source_ip).order_by(
                func.count(AlertRecord.id).desc()
            ).limit(10).all()
            
            for source, count in source_counts:
                stats['by_source'][source] = count
            
            # Averages
            avg_risk = session.query(func.avg(AlertRecord.risk_score)).scalar()
            avg_confidence = session.query(func.avg(AlertRecord.confidence)).scalar()
            
            stats['average_risk_score'] = float(avg_risk) if avg_risk else 0
            stats['average_confidence'] = float(avg_confidence) if avg_confidence else 0
            
            return stats
            
        except SQLAlchemyError as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
        finally:
            session.close()
    
    def get_time_series(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get alert time series data
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of time series data points
        """
        session = self.get_session()
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            
            # Group by hour
            records = session.query(
                func.strftime('%Y-%m-%d %H:00:00', AlertRecord.timestamp).label('hour'),
                func.count(AlertRecord.id).label('count')
            ).filter(
                AlertRecord.timestamp >= cutoff_time
            ).group_by('hour').order_by('hour').all()
            
            return [
                {'timestamp': hour, 'count': count}
                for hour, count in records
            ]
        except SQLAlchemyError as e:
            logger.error(f"Failed to get time series: {e}")
            return []
        finally:
            session.close()
    
    def add_flow_statistics(self, stats: Dict[str, Any]) -> bool:
        """
        Add flow statistics to database
        
        Args:
            stats: Dictionary with flow statistics
            
        Returns:
            True if successful
        """
        session = self.get_session()
        try:
            record = FlowStatisticsRecord(
                timestamp=datetime.now(timezone.utc),
                total_flows=stats.get('total_flows', 0),
                total_packets=stats.get('total_packets', 0),
                total_bytes=stats.get('total_bytes', 0),
                unique_sources=stats.get('unique_sources', 0),
                unique_destinations=stats.get('unique_destinations', 0),
                stats_json=json.dumps(stats)
            )
            session.add(record)
            session.commit()
            return True
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to add flow statistics: {e}")
            return False
        finally:
            session.close()
    
    def clear_all_alerts(self) -> int:
        """
        Clear all alerts from database
        
        Returns:
            Number of alerts deleted
        """
        session = self.get_session()
        try:
            count = session.query(AlertRecord).count()
            session.query(AlertRecord).delete()
            session.commit()
            logger.info(f"Cleared {count} alerts")
            return count
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to clear alerts: {e}")
            return 0
        finally:
            session.close()
    
    def close(self):
        """Close database connection"""
        try:
            self.engine.dispose()
            logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Failed to close database: {e}")