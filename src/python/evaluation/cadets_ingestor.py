import json
import logging
from typing import Dict, Any, Generator, Optional
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ipg_encoder import KernelEvent, SyscallType

logger = logging.getLogger("sentinel.eval.ingestor")

class CadetsIngestor:
    """
    Streaming parser for the DARPA TC Common Data Model (CDM).
    Reads massive JSON files line-by-line to prevent RAM exhaustion.
    Maps Subject and Object UUIDs to Sentinel's KernelEvent structure.
    """
    def __init__(self, file_path: str):
        self.file_path = file_path
        # In-memory maps to link UUIDs from the DARPA JSON to actual values
        self.subjects: Dict[str, Dict[str, Any]] = {}
        self.objects: Dict[str, str] = {}
        
        # Simple mapping from DARPA event types to our SyscallType
        self.type_map = {
            "EVENT_READ": SyscallType.FILE_R.value,
            "EVENT_WRITE": SyscallType.FILE_W.value,
            "EVENT_OPEN": SyscallType.FILE_R.value,
            "EVENT_EXECUTE": SyscallType.EXEC.value,
            "EVENT_SENDTO": SyscallType.NET_CON.value,
            "EVENT_CONNECT": SyscallType.NET_CON.value
        }

    def _process_subject(self, record: dict):
        uuid = record.get("uuid")
        if uuid:
            # Subjects are processes. We want the PID and the command name.
            properties = record.get("properties", {})
            self.subjects[uuid] = {
                "pid": record.get("cid", 0),  # Rough approximation, CADETS uses cid for thread/process ID
                "comm": properties.get("name", "unknown")
            }

    def _process_object(self, record: dict, record_type: str):
        uuid = record.get("uuid")
        if uuid:
            if record_type in ("FileObject", "UnnamedPipeObject", "RegistryKeyObject"):
                base = record.get("baseObject", {})
                props = base.get("properties", {})
                if isinstance(props, dict):
                    pmap = props.get("map", {})
                    self.objects[uuid] = pmap.get("path") or pmap.get("filename") or pmap.get("name") or "/unknown"
            elif record_type == "NetFlowObject":
                remote_ip = record.get("remoteAddress", "")
                remote_port = record.get("remotePort")
                if remote_ip and remote_port:
                    self.objects[uuid] = f"{remote_ip}:{remote_port}"

    def _pass1_build_entities(self):
        logger.info(f"Pass 1: building entity maps from {self.file_path} ...")
        with open(self.file_path, 'r') as f:
            for line in f:
                try:
                    record = json.loads(line.strip())
                    if "datum" not in record:
                        continue
                    
                    datum = record["datum"]
                    full_record_type = list(datum.keys())[0]
                    record_type = full_record_type.split('.')[-1]
                    data = datum[full_record_type]
                    
                    if record_type == "Subject":
                        self._process_subject(data)
                    elif record_type in ("FileObject", "UnnamedPipeObject", "RegistryKeyObject", "NetFlowObject"):
                        self._process_object(data, record_type)
                except Exception:
                    continue
        logger.info("Pass 1 done.")

    def stream_events(self) -> Generator[KernelEvent, None, None]:
        """
        Yields Sentinel KernelEvent objects by reading the CDM JSON-lines file.
        Uses two passes to resolve CDM18 forward-references (e.g. NetFlowObject after Event).
        """
        logger.info(f"Starting stream from {self.file_path}")
        
        if not os.path.exists(self.file_path):
            logger.warning(f"Dataset file {self.file_path} not found. Returning empty stream.")
            return

        self._pass1_build_entities()

        logger.info("Pass 2: emitting events ...")
        with open(self.file_path, 'r') as f:
            for line in f:
                try:
                    record = json.loads(line.strip())
                    
                    if "datum" not in record:
                        continue
                    
                    datum = record["datum"]
                    full_record_type = list(datum.keys())[0]
                    record_type = full_record_type.split('.')[-1]
                    data = datum[full_record_type]
                    
                    if record_type == "Event":
                        # Map the event
                        evt_type = data.get("type")
                        if evt_type not in self.type_map:
                            continue
                            
                        subj_uuid = data.get("subject", {}).get("com.bbn.tc.schema.avro.cdm18.UUID")
                        obj_uuid = data.get("predicateObject", {}).get("com.bbn.tc.schema.avro.cdm18.UUID")
                        
                        subj_info = self.subjects.get(subj_uuid, {"pid": 0, "comm": "unknown"})
                        resource = self.objects.get(obj_uuid, "")
                        
                        # Fallbacks for exec paths and IPs that skip Object UUIDs
                        props = data.get("properties", {}).get("map", {})
                        if evt_type == "EVENT_EXECUTE":
                            exec_path = data.get("predicateObjectPath", {}).get("string")
                            if exec_path:
                                resource = exec_path
                            elif props.get("exec"):
                                subj_info["comm"] = props.get("exec")
                                
                        if not resource and evt_type == "EVENT_CONNECT":
                            resource = props.get("address", "")
                            
                        yield KernelEvent(
                            ts_ns=data.get("timestampNanos", 0),
                            pid=subj_info["pid"],
                            ppid=0, # DARPA doesn't map ppid directly in Event, needs Subject hierarchy traversal
                            uid=0,
                            comm=subj_info["comm"][:15],
                            sc_type=self.type_map[evt_type],
                            resource=resource,
                            flags=0,
                            net_port=0,
                            net_ip4=0
                        )
                except Exception as e:
                    # Ignore malformed lines
                    continue

    def get_windows(self, window_size: int = 20) -> Generator[list[KernelEvent], None, None]:
        """Yields windows of events for the pipeline."""
        window = []
        for event in self.stream_events():
            window.append(event)
            if len(window) == window_size:
                yield window
                window = []
        
        if window:
            yield window

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ingestor = CadetsIngestor("/Volumes/Extreme SSD/DARPA_TC/ta1-cadets-e3-official.json")
    
    count = 0
    for w in ingestor.get_windows(20):
        print(f"Extracted window with {len(w)} events. First event comm: {w[0].comm}")
        count += 1
        if count >= 5:
            break
