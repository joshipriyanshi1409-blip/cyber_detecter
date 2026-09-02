"""
Complete Pipeline Integration
Connects all components: ingestion → flow → features → detection → alerts → storage.
"""

import logging
import time
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime, timezone
import json
import os

from src.flow.nfstream_wrapper import FlowExtractor, FlowRecord
from src.detectors.detector_factory import DetectorFactory, DetectorType
from src.alerts.alert_engine import AlertEngine, AlertProcessor
from src.alerts.alert_models import Alert
from src.storage.database import DatabaseManager
from src.risk.authoritative_risk import Evidence, calculate_risk
from src.flow_normalization import validate_canonical_flow
from src.blockchain.hash_chain import HashChain
from src.cti.enrichment import ThreatIntelligenceEnricher
from src.models.isolation_forest import IsolationForestAnomalyDetector
from src.models.random_forest import RandomForestThreatClassifier
from src.models.artifact_security import verify_model_artifact, ModelIntegrityError
from src.streaming.windowing import WindowAggregator
from src.detectors.contracts import DetectionResult
import hashlib

try:
    from src.utils.config import config_manager
except ImportError:
    from src.utils.config_simple import config_manager

try:
    from src.utils.logging import setup_logging
except ImportError:
    def setup_logging(level="INFO"):
        logging.basicConfig(level=getattr(logging, level.upper()))
        return logging.getLogger()

logger = logging.getLogger(__name__)


class ThreatDetectionPipeline:
    """Complete threat detection pipeline"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize pipeline
        
        Args:
            config: Pipeline configuration
        """
        self.config = config or {}
        
        # Initialize components
        self.flow_extractor = FlowExtractor()
        configured_detectors = self.config.get("detection", {}).get("enabled_detectors")
        if configured_detectors is None:
            configured_detectors = self.config.get("enabled_detectors")
        if configured_detectors is None:
            configured_detectors = config_manager.get(
                "main", "detection", "enabled_detectors",
                default=["ddos","c2","dns_threat","encrypted_session","port_scan","exfiltration","syn_flood","udp_flood"],
            )
        self.detector_factory = DetectorFactory(configured_detectors)
        if self.detector_factory.initialization_errors:
            raise RuntimeError(
                "Mandatory detector initialization failed: "
                + repr(self.detector_factory.initialization_errors)
            )
        self.alert_processor = AlertProcessor()
        # Final risk is calculated only by _apply_authoritative_risk().
        self.hash_chain = HashChain(
            self.config.get('hash_chain_file', 'data/hash_chain.json')
        )
        # config dict (explicit constructor arg) wins over thresholds.yaml
        # if the caller passed one, so tests/scripts overriding config={}
        # keep working exactly as before.
        self.cti_enricher = ThreatIntelligenceEnricher(
            max_lookups_per_window=self.config.get(
                'cti_max_lookups_per_window',
                config_manager.get_threshold("cti", "max_lookups_per_window", default=60),
            ),
            rate_limit_window_seconds=self.config.get(
                'cti_rate_limit_window_seconds',
                config_manager.get_threshold("cti", "rate_limit_window_seconds", default=60.0),
            ),
        )
        
        # Database
        db_path = self.config.get('database_path', 'data/threats.db')
        self.database = DatabaseManager(db_path)
        
        # ML models (optional)
        self.isolation_forest = None
        self.random_forest = None
        
        # Statistics
        self.stats = {
            'flows_processed': 0,
            'detections_found': 0,
            'alerts_created': 0,
            'alerts_stored': 0,
            'start_time': None,
            'end_time': None
        }
        
        logger.info("Initialized ThreatDetectionPipeline")
    
    def load_models(self, isolation_forest_path: Optional[str] = None,
                   random_forest_path: Optional[str] = None):
        """Load only integrity-verified trusted ML artifacts."""
        model_cfg = self.config.get("ml", {}).get("model_integrity", {})
        require_hash = bool(model_cfg.get("require_hash", True))

        if isolation_forest_path and Path(isolation_forest_path).exists():
            verify_model_artifact(
                isolation_forest_path,
                os.getenv("CYBER_DETECTER_ISOLATION_FOREST_SHA256"),
                require_hash=require_hash,
            )
            self.isolation_forest = IsolationForestAnomalyDetector()
            if not self.isolation_forest.load_model(isolation_forest_path):
                raise ModelIntegrityError(
                    f"failed to load verified Isolation Forest artifact: {isolation_forest_path}"
                )
            logger.info("Loaded verified Isolation Forest from %s", isolation_forest_path)

        if random_forest_path and Path(random_forest_path).exists():
            verify_model_artifact(
                random_forest_path,
                os.getenv("CYBER_DETECTER_RANDOM_FOREST_SHA256"),
                require_hash=require_hash,
            )
            self.random_forest = RandomForestThreatClassifier()
            if not self.random_forest.load_model(random_forest_path):
                raise ModelIntegrityError(
                    f"failed to load verified Random Forest artifact: {random_forest_path}"
                )
            logger.info("Loaded verified Random Forest from %s", random_forest_path)

    def process_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """Process PCAP traffic through the same window/ML/risk path used by LIVE."""
        self.stats['start_time']=datetime.now(timezone.utc)
        results={"pcap_file":pcap_file,"flows":[],"detections":{},"alerts":[],"windows":[],"statistics":{}}
        try:
            flows=self.flow_extractor.extract_from_pcap(pcap_file)
            for flow in flows: validate_canonical_flow(flow)
            self.stats["flows_processed"]=len(flows); results["flows"]=flows
            if not flows:
                results["status"]="OK_EMPTY"
                results["pipeline_stats"]=self.stats.copy()
                self.stats["end_time"]=datetime.now(timezone.utc)
                return results
            cfg=self.config.get("streaming",{}).get("windowing",{})
            aggregator=WindowAggregator(float(cfg.get("window_seconds",10)),float(cfg.get("slide_seconds",1)))
            for window_data in aggregator.add_many(flows):
                wr=self._process_window(window_data, persist=True)
                results["windows"].append(wr); results["alerts"].extend(wr["alerts"])
            final=aggregator.flush()
            if final:
                wr=self._process_window(final,persist=True)
                results["windows"].append(wr); results["alerts"].extend(wr["alerts"])
            results["detections"]={k:v for w in results["windows"] for k,v in w["detections"].items()}
            self.stats["alerts_created"]=len(results["alerts"])
            self.stats["alerts_stored"]=sum(w.get("alerts_stored",0) for w in results["windows"])
            self.stats["end_time"]=datetime.now(timezone.utc)
            results["statistics"]={"flows":self.flow_extractor.get_flow_statistics(),
                                   "alerts":self.alert_processor.engine.get_statistics(results["alerts"]),
                                   "database":self.database.get_statistics(),
                                   "hash_chain":self.hash_chain.get_chain_statistics()}
            results["pipeline_stats"]=self.stats.copy(); results["status"]="OK"
            return results
        except Exception as e:
            logger.error("Pipeline failed: %s",e,exc_info=True)
            self.stats["end_time"]=datetime.now(timezone.utc)
            results["pipeline_stats"]=self.stats.copy()
            results["status"]=self._classify_error(e)
            results["error_type"]=type(e).__name__
            # Never turn a parser/detector/ML failure into "no threat".
            results["error"]=str(e)
            return results

    def _run_ml(self, flows, window_id):
        """Run configured, trained ML models and return real predictions only."""
        predictions=[]
        ml_status=[]
        if self.isolation_forest is not None:
            if self.isolation_forest.is_trained:
                started=time.perf_counter()
                for pred in self.isolation_forest.predict(flows):
                    pred["inference_time_ms"]=(time.perf_counter()-started)*1000.0
                    predictions.append(pred)
                ml_status.append("isolation_forest")
            else:
                ml_status.append("isolation_forest_untrained")
        if self.random_forest is not None:
            if self.random_forest.is_trained:
                started=time.perf_counter()
                for pred in self.random_forest.predict(flows):
                    pred["inference_time_ms"]=(time.perf_counter()-started)*1000.0
                    predictions.append(pred)
                ml_status.append("random_forest")
            else:
                ml_status.append("random_forest_untrained")
        return predictions, ml_status

    @staticmethod
    def _correlate_ml(detections, predictions):
        """Attach ML evidence strictly by flow_id, never by source IP."""
        by_flow={}
        for pred in predictions:
            flow=pred.get("flow")
            if flow is None or getattr(flow,"flow_id",None) is None: continue
            by_flow.setdefault(str(flow.flow_id),[]).append(pred)
        for det in detections:
            ids=list(getattr(det,"flow_ids",()) or ())
            if not ids:
                detail=getattr(det,"details",{}) or {}
                if detail.get("flow_id") is not None: ids=[str(detail["flow_id"])]
            matched=[p for fid in ids for p in by_flow.get(str(fid),[])]
            if matched:
                rf=[p for p in matched if p.get("model_name")=="random_forest"]
                if rf:
                    best=max(rf,key=lambda p:p.get("confidence",0))
                    det.details["ml_prediction"]=best.get("predicted_class")
                    det.details["ml_probability"]=best.get("confidence")
                    det.details["ml_probabilities"]=best.get("probabilities",{})
                    det.details["ml_model_version"]=best.get("model_version")
                    det.details["ml_ran"]=True
                anomaly=[p for p in matched if p.get("model_name")=="isolation_forest"]
                if anomaly:
                    best=max(anomaly,key=lambda p:p.get("anomaly_score",0))
                    det.details["anomaly_score"]=best.get("anomaly_score")
                    det.details["is_anomaly"]=best.get("is_anomaly")
                    det.details["ml_anomaly_score"]=best.get("anomaly_score")
                    det.details["ml_ran"]=True
        return detections

    def _process_window(self, window_data, *, persist=True):
        """ONE authoritative downstream processing function for PCAP and LIVE."""
        flows=list(window_data.get("flows",()))
        for flow in flows: validate_canonical_flow(flow)
        quality="GOOD"; degradation=[]
        if window_data.get("expired_count",0)>0:
            degradation.append("flow_eviction_or_window_expiry")
        detections=self.detector_factory.run_all_detectors(flows) if flows else {}
        flat=[d for values in detections.values() for d in values]
        predictions,ml_status=self._run_ml(flows,window_data.get("window_id"))
        self._correlate_ml(flat,predictions)

        # ML-only alerts: a real anomaly or non-normal RF label is independently alertable.
        known_flow_ids={str(fid) for d in flat for fid in getattr(d,"flow_ids",())}
        for pred in predictions:
            flow=pred.get("flow")
            if flow is None or str(getattr(flow,"flow_id",None)) in known_flow_ids: continue
            if pred.get("model_name")=="isolation_forest" and pred.get("is_anomaly"):
                ids=(str(flow.flow_id),)
                flat.append(DetectionResult(
                    detector="isolation_forest",detected=True,attack_type="ML_ANOMALY",
                    attack_subtype="behavioral_anomaly",flow_ids=ids,source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,source_port=flow.source_port,destination_port=flow.destination_port,
                    protocol=flow.protocol,event_start_time=flow.timestamp,event_end_time=flow.timestamp,
                    rule_score=0.0,rule_confidence=0.0,
                    evidence={"ml_anomaly_score":pred.get("anomaly_score"),"ml_status":"EXECUTED"},
                    details={"ml_ran":True}))
            elif pred.get("model_name")=="random_forest" and pred.get("predicted_class") not in (None,"NORMAL"):
                ids=(str(flow.flow_id),)
                prob=float(pred.get("confidence",0.0))
                flat.append(DetectionResult(
                    detector="random_forest",detected=True,attack_type="ML_CLASSIFICATION",
                    attack_subtype=str(pred.get("predicted_class")).lower(),flow_ids=ids,
                    source_ip=flow.source_ip,destination_ip=flow.destination_ip,source_port=flow.source_port,
                    destination_port=flow.destination_port,protocol=flow.protocol,event_start_time=flow.timestamp,
                    event_end_time=flow.timestamp,rule_score=0.0,rule_confidence=0.0,
                    evidence={"ml_probability":prob,"ml_label":pred.get("predicted_class"),"ml_status":"EXECUTED"},
                    details={"ml_ran":True}))

        # Convert to alerts only after all rule+ML evidence is attached.
        alerts=self.alert_processor.process_flat_detections(flat)
        for alert in alerts:
            alert.window_id=window_data.get("window_id")
            if not alert.event_time and window_data.get("window_end_ms"):
                alert.event_time=datetime.fromtimestamp(window_data.get("window_end_ms")/1000.0,tz=timezone.utc).isoformat()
            alert.observation_quality=quality
            alert.degradation_reasons=list(degradation)
            alert.ml_ran=bool(predictions)
            alert.details.setdefault("ml_status","EXECUTED" if predictions else "UNAVAILABLE")
            if not predictions: alert.details["ml_unavailable_reason"]="no_trained_model_loaded"
            # Protocol/ports belong in the alert identity.
            if alert.source_ip or alert.destination_ip:
                alert.details.setdefault("protocol", next((getattr(d,"protocol",None) for d in flat if getattr(d,"source_ip","")==alert.source_ip), None))
            alert.details.setdefault("window_id",window_data.get("window_id"))
            alert.details.setdefault("observation_quality",quality)

        alerts=self.cti_enricher.batch_enrich(alerts)
        for alert in alerts:
            if alert.cti_status=="PARTIAL": alert.observation_quality="DEGRADED"; alert.degradation_reasons.append("cti_partial")
            self._apply_authoritative_risk(alert)
            alert.incident_id=self._incident_id(alert)
        stored=0
        if persist and alerts:
            stored=self.database.add_alerts(alerts)
            self.hash_chain.append_alerts(alerts)
        return {"window_id":window_data.get("window_id"),"window_start_ms":window_data.get("window_start_ms"),
                "window_end_ms":window_data.get("window_end_ms"),"flow_count":len(flows),
                "source_count":window_data.get("source_count",0),"observation_quality":quality,
                "degradation_reasons":degradation,"detections":detections,"alerts":alerts,
                "alerts_stored":stored,"ml_status":ml_status,"ml_predictions":predictions}

    @staticmethod
    def _incident_id(alert):
        bucket=alert.event_time or alert.processing_time
        try: bucket=datetime.fromisoformat(bucket).timestamp()//60
        except Exception: bucket=0
        endpoints="|".join(sorted([alert.source_ip or "",alert.destination_ip or ""]))
        return hashlib.sha256(f"{endpoints}|{bucket}".encode()).hexdigest()[:24]

    @staticmethod
    def _apply_authoritative_risk(alert: Alert) -> Alert:
        """Calculate final risk from explicit, real evidence sources only."""
        now=datetime.now(timezone.utc); evidence=[]
        rule_score=float(alert.rule_score or 0.0)
        rule_conf=float(alert.rule_confidence or 0.0)
        if rule_score>0 or alert.attack_type:
            evidence.append(Evidence(source="rule",detector=alert.detector or "unknown",
                feature="rule_score",raw_value=rule_score,threshold=None,
                contribution=max(0,min(100,rule_score*100)),reason="Detector rule evidence",timestamp=now))
        if alert.ml_probability is not None:
            p=max(0,min(1,float(alert.ml_probability)))
            evidence.append(Evidence(source="ml",detector=alert.detector or "ml",
                feature="ml_probability",raw_value=p,threshold=None,contribution=p*20,
                reason="Real supervised ML inference",timestamp=now))
        if alert.ml_anomaly_score is not None:
            a=max(0,min(1,float(alert.ml_anomaly_score)))
            evidence.append(Evidence(source="ml",detector=alert.detector or "ml",
                feature="ml_anomaly_score",raw_value=a,threshold=None,contribution=a*15,
                reason="Real Isolation Forest anomaly score",timestamp=now))
        cti=alert.details.get("cti_risk_contribution")
        if cti is not None:
            c=float(cti)
            evidence.append(Evidence(source="cti",detector="threat_intelligence",
                feature="cti_risk_contribution",raw_value=c,threshold=None,contribution=c,
                reason="CTI malicious-indicator evidence",timestamp=now))
            alert.cti_score=c
        result=calculate_risk(evidence)
        alert.risk_score=result.score
        alert.risk_breakdown=list(result.breakdown)
        # Decision confidence is a fusion measure, not max() of unrelated scores.
        components=[]
        if rule_conf>0: components.append(rule_conf)
        if alert.ml_probability is not None: components.append(float(alert.ml_probability)*0.7)
        if alert.cti_score is not None: components.append(min(1.0,float(alert.cti_score)/100.0)*0.5)
        alert.decision_confidence=1.0
        for c in components: alert.decision_confidence *= (1.0-max(0,min(1,c)))
        alert.decision_confidence=1.0-alert.decision_confidence if components else 0.0
        alert.confidence=rule_conf  # compatibility alias only
        if alert.risk_score>=81: alert.severity="CRITICAL"
        elif alert.risk_score>=61: alert.severity="HIGH"
        elif alert.risk_score>=31: alert.severity="MEDIUM"
        else: alert.severity="LOW"
        return alert

    def process_flow_stream(
        self,
        flows,
        window_seconds: float = 10.0,
        slide_seconds: float = 1.0,
        on_window=None,
        persist: bool = False,
    ) -> List[Dict[str, Any]]:
        """Run timestamped flows through the same rolling detector/risk path.

        PCAP replay and live callers therefore share detector, CTI, and
        authoritative-risk semantics. Persistence is opt-in for replay/tests.
        """
        aggregator = WindowAggregator(window_seconds, slide_seconds)
        results = []

        for flow in flows:
            validate_canonical_flow(flow)
            for window in aggregator.add(flow):
                result = self._process_live_window(window, persist=persist)
                if on_window is not None:
                    on_window(result)
                results.append(result)

        final_window = aggregator.flush()
        if final_window is not None:
            result = self._process_live_window(final_window, persist=persist)
            if on_window is not None:
                on_window(result)
            results.append(result)

        return results

    def process_live(
        self,
        interface: str,
        duration: int = 60,
        packet_filter: str = "",
        queue_size: int = 5000,
    ) -> Dict[str, Any]:
        """Run actual live detection while capture is still active.

        Packets are drained continuously from the bounded capture queue,
        converted into bounded flow state, and evaluated in rolling event-time
        windows. No temporary PCAP/replay is required.
        """
        if duration <= 0:
            raise ValueError("duration must be positive")

        import time as _time
        from src.ingest.live_capture import LivePacketCapture
        from src.flow.nfstream_wrapper import IncrementalScapyFlowAggregator

        window_cfg = self.config.get("streaming", {}).get("windowing", {})
        window_seconds = float(window_cfg.get("window_seconds", 10))
        slide_seconds = float(window_cfg.get("slide_seconds", 1))
        max_buffered_flows = int(window_cfg.get("max_buffered_flows", 100000))

        capture = LivePacketCapture(
            interface=interface,
            packet_filter=packet_filter,
            queue_size=queue_size,
            drop_on_full=True,
            retain_packets=False,
        )
        flow_builder = IncrementalScapyFlowAggregator(max_buffered_flows)
        window = WindowAggregator(window_seconds, slide_seconds)

        capture.start_capture(duration=duration)
        start = _time.monotonic()
        next_emit = start + slide_seconds
        all_alerts = []
        all_windows = []
        window_errors = []

        while _time.monotonic() - start < duration or capture.is_capturing or capture.packet_queue.qsize():
            packets = capture.drain_queue(max_items=1000)
            for packet in packets:
                try:
                    flow_builder.add_packet(packet)
                except Exception as exc:
                    window_errors.append({
                        "status": "INGESTION_ERROR",
                        "error_type": type(exc).__name__,
                        "message": str(exc),
                    })

            now = _time.monotonic()
            if now >= next_emit:
                flows = flow_builder.snapshot()
                if flows:
                    for window_data in window.add_many(flows):
                        window_result = self._process_live_window(window_data, persist=True)
                        all_windows.append(window_result)
                        all_alerts.extend(window_result["alerts"])
                next_emit = now + slide_seconds

            if not capture.is_capturing and not packets:
                break
            _time.sleep(0.02)

        capture.stop_capture()
        capture.wait(timeout=5)

        # Flush remaining packet queue and final flow/window state.
        for packet in capture.drain_queue():
            try:
                flow_builder.add_packet(packet)
            except Exception as exc:
                window_errors.append({
                    "status": "INGESTION_ERROR",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                })
        final_flows = flow_builder.snapshot()
        if final_flows:
            for window_data in window.add_many(final_flows):
                window_result = self._process_live_window(window_data, persist=True)
                all_windows.append(window_result)
                all_alerts.extend(window_result["alerts"])
        final_window = window.flush()
        if final_window:
            window_result = self._process_live_window(final_window, persist=True)
            all_windows.append(window_result)
            all_alerts.extend(window_result["alerts"])

        capture_stats = capture.get_statistics()
        capture_stats["flow_evictions"] = flow_builder.evicted_flows
        degraded = bool(window_errors or capture_stats.get("error") or
                        capture_stats.get("dropped_packets",0) or flow_builder.evicted_flows)
        if degraded:
            reasons=[]
            if window_errors: reasons.append("parser_or_ingestion_error")
            if capture_stats.get("dropped_packets",0): reasons.append("capture_queue_drops")
            if flow_builder.evicted_flows: reasons.append("flow_state_evictions")
            for wr in all_windows:
                wr["observation_quality"]="DEGRADED"
                wr["degradation_reasons"]=sorted(set(wr.get("degradation_reasons",[])+reasons))
                for alert in wr.get("alerts",[]):
                    alert.observation_quality="DEGRADED"
                    alert.degradation_reasons=sorted(set(alert.degradation_reasons+reasons))
        status = "DEGRADED" if degraded else "OK"
        return {
            "status": status,
            "mode": "LIVE",
            "interface": interface,
            "windows": all_windows,
            "alerts": all_alerts,
            "capture": capture_stats,
            "errors": window_errors,
            "pipeline_stats": {
                "windows_processed": len(all_windows),
                "alerts_created": len(all_alerts),
                "dropped_packets": capture_stats.get("dropped_packets", 0),
                "flow_evictions": flow_builder.evicted_flows,
            },
        }

    def _process_live_window(self, window_data: Dict[str, Any], *, persist: bool = True) -> Dict[str, Any]:
        """Run one live event-time window through detection and persistence."""
        result=self._process_window(window_data,persist=persist)
        result["source_churn"]=window_data.get("source_churn")
        return result

    @staticmethod
    def _classify_error(error: Exception) -> str:
        name = type(error).__name__.lower()
        message = str(error).lower()
        if "pcap" in name or "pcap" in message or "scapy" in message:
            return "PARSER_ERROR"
        if "database" in name or "sql" in name or "sqlite" in message:
            return "STORAGE_ERROR"
        if "model" in name or "model" in message or "ml" in message:
            return "ML_ERROR"
        if "config" in name or "config" in message:
            return "CONFIGURATION_ERROR"
        if "detector" in message:
            return "DETECTOR_ERROR"
        return "INGESTION_ERROR"

    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get pipeline status"""
        return {
            'stats': self.stats,
            'components': {
                'flow_extractor': self.flow_extractor is not None,
                'detector_factory': self.detector_factory is not None,
                'alert_processor': self.alert_processor is not None,
                'risk_engine': True,
                'hash_chain': self.hash_chain is not None,
                'cti_enricher': self.cti_enricher is not None,
                'database': self.database is not None,
                'isolation_forest': self.isolation_forest is not None,
                'random_forest': self.random_forest is not None
            }
        }
    
    def export_results(self, results: Dict[str, Any], output_file: str):
        """Export pipeline results to JSON"""
        try:
            # Convert to serializable format
            export_data = {
                'pcap_file': results.get('pcap_file'),
                'statistics': results.get('statistics'),
                'pipeline_stats': results.get('pipeline_stats'),
                'alerts': [
                    alert.to_dict() if hasattr(alert, 'to_dict') else str(alert)
                    for alert in results.get('alerts', [])
                ]
            }
            
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Exported results to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return False