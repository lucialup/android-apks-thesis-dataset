import re
import os
import sys
import json
import csv
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict


THREAD_PATTERNS = {
    "okhttp": r"OkHttp.*",
    "okhttp_task": r"OkHttp TaskRunn.*", 
    "rxjava": r"Rx(Cached|Computation|IO|Single|NewThread|Scheduler).*",
    "rxjava_cached": r"RxCachedThreadS.*",
    "coroutines": r"DefaultDispatch.*",
    "workmanager": r"WM\.task.*",
    "workmanager_alt": r"androidx\.work.*",  
    "room_io": r"arch_disk_io.*",

    "glide": r"[Gg]lide.*",
    "glide_source": r"glide-source-th.*",  
    "glide_disk": r"glide-disk-cach.*",  
    "coil": r"[Cc]oil.*", 
    "fresco": r"[Ff]resco.*",

    "binder": r"binder:.*",
    "async_task": r"AsyncTask.*",
    "thread_pool": r"pool-\d+-thread-\d+",
    "exoplayer": r"ExoPlayer.*", 
    "flutter": r"(flutter-worker-|DartWorker).*", 
    "render_thread": r"RenderThread.*", 
}

PATH_PATTERNS = {
    "room_wal": r"\.db-wal$",
    "room_shm": r"\.db-shm$",
    "room_journal": r"\.db-journal$", 
    "workmanager_db": r"androidx\.work\.workdb",
    "datastore": r"datastore.*\.preferences_pb$",
    "okhttp_cache": r"okHttpCache",
    "okhttp_cache_dir": r"/cache/okhttp/",  
    "okhttp_journal": r"okhttp.*journal",  

    "glide_cache": r"(glide|image_manager_disk_cache)",
    "glide_journal": r"image_manager_disk_cache.*journal",  
    "coil_cache": r"(coil|image_loader)",
    "coil_cache_v3": r"coil3?_disk_cache", 
    "coil_journal": r"coil.*journal", 
    "fresco_cache": r"(fresco|imagepipeline)",

    "database": r"\.db$",
    "sqlite": r"\.sqlite$",  
    "sqlite_journal": r"\.sqlite-journal$",  
    "shared_prefs": r"shared_prefs.*\.xml$",
    "native_lib": r"\.so$",

    "cacerts": r"cacerts", 
    "http_cache": r"HTTP.*[Cc]ache", 
}


@dataclass
class SyscallRecord:
    timestamp: str = ""
    syscall: str = ""
    pid: int = 0
    tid: int = 0
    uid: int = 0
    comm: str = ""
    path: str = ""
    fd: int = -1
    flags: str = ""
    count: int = 0
    actual: int = 0
    family: str = ""
    ip: str = ""
    port: int = 0
    child_pid: int = 0
    clone_type: str = ""
    prot: str = ""
    raw_line: str = ""


def parse_syscall_line(line: str) -> Optional[SyscallRecord]:
    if not line.strip() or line.startswith('#'):
        return None

    record = SyscallRecord(raw_line=line)

    pattern = r'(\w+)=("([^"]*)"|(\S+))'

    for match in re.finditer(pattern, line):
        key = match.group(1)
        value = match.group(3) if match.group(3) is not None else match.group(4)

        if key == 'ts':
            record.timestamp = value
        elif key == 'syscall':
            record.syscall = value
        elif key == 'pid':
            record.pid = int(value)
        elif key == 'tid':
            record.tid = int(value)
        elif key == 'uid':
            record.uid = int(value)
        elif key == 'comm':
            record.comm = value
        elif key == 'path':
            record.path = value
        elif key == 'fd':
            record.fd = int(value)
        elif key == 'flags':
            record.flags = value
        elif key == 'count':
            record.count = int(value)
        elif key == 'actual':
            record.actual = int(value)
        elif key == 'family':
            record.family = value
        elif key == 'ip':
            record.ip = value
        elif key == 'port':
            record.port = int(value)
        elif key == 'child_pid':
            record.child_pid = int(value)
        elif key == 'type':
            record.clone_type = value
        elif key == 'prot':
            record.prot = value

    return record if record.syscall else None


def parse_syscall_log(filepath: str) -> List[SyscallRecord]:
    records = []

    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            record = parse_syscall_line(line)
            if record:
                records.append(record)

    return records


@dataclass
class AppFeatures:
    package: str = ""
    total_syscalls: int = 0
    trace_duration_sec: float = 0.0

    has_okhttp_thread: bool = False
    has_okhttp_task_thread: bool = False 
    has_rxjava_thread: bool = False
    has_rxjava_cached_thread: bool = False 
    has_coroutine_thread: bool = False
    has_workmanager_thread: bool = False
    has_workmanager_alt_thread: bool = False 
    has_room_io_thread: bool = False

    has_glide_thread: bool = False
    has_glide_source_thread: bool = False  
    has_glide_disk_thread: bool = False  
    has_coil_thread: bool = False 
    has_fresco_thread: bool = False

    has_exoplayer_thread: bool = False  
    has_flutter_thread: bool = False  
    has_async_task_thread: bool = False  

    has_room_wal: bool = False
    has_room_shm: bool = False
    has_room_journal: bool = False 
    has_workmanager_db: bool = False
    has_datastore: bool = False
    has_okhttp_cache: bool = False
    has_okhttp_cache_dir: bool = False  
    has_okhttp_journal: bool = False  

    has_glide_cache: bool = False
    has_glide_journal: bool = False  
    has_coil_cache: bool = False
    has_coil_cache_v3: bool = False  
    has_coil_journal: bool = False 
    has_fresco_cache: bool = False

    has_cacerts_access: bool = False 
    has_http_cache: bool = False  

    has_ipv4_connect: bool = False  
    has_ipv6_connect: bool = False  
    num_port_443_connects: int = 0 

    num_unique_threads: int = 0
    num_threads_spawned: int = 0
    num_databases: int = 0
    num_shared_prefs: int = 0
    num_native_libs: int = 0
    num_tcp_sockets: int = 0
    num_udp_sockets: int = 0
    num_unix_sockets: int = 0
    num_network_connects: int = 0
    num_unique_ips: int = 0

    num_openat: int = 0
    num_read: int = 0
    num_write: int = 0
    num_close: int = 0
    num_clone: int = 0
    num_mmap: int = 0
    num_socket: int = 0
    num_connect: int = 0

    total_bytes_read: int = 0
    total_bytes_written: int = 0

    syscalls_per_second: float = 0.0
    threads_per_second: float = 0.0

    _thread_names: Set[str] = field(default_factory=set)
    _file_paths: Set[str] = field(default_factory=set)
    _ip_addresses: Set[str] = field(default_factory=set)


def extract_features(records: List[SyscallRecord], package: str = "") -> AppFeatures:
    """
    Extract features from a list of syscall records.
    """
    features = AppFeatures(package=package)

    if not records:
        return features

    features.total_syscalls = len(records)

    thread_names: Set[str] = set()
    file_paths: Set[str] = set()
    ip_addresses: Set[str] = set()
    database_files: Set[str] = set()

    first_ts = None
    last_ts = None

    for record in records:
        if record.timestamp:
            if first_ts is None:
                first_ts = record.timestamp
            last_ts = record.timestamp

        if record.comm:
            thread_names.add(record.comm)

        if record.path:
            file_paths.add(record.path)

        syscall = record.syscall

        if syscall == 'openat' or syscall == 'open':
            features.num_openat += 1

            if record.path.endswith('.db'):
                database_files.add(record.path)

        elif syscall == 'read':
            features.num_read += 1
            features.total_bytes_read += record.actual

        elif syscall == 'write':
            features.num_write += 1
            features.total_bytes_written += record.actual

        elif syscall == 'close':
            features.num_close += 1

        elif syscall == 'clone':
            features.num_clone += 1
            if record.clone_type == 'thread':
                features.num_threads_spawned += 1

        elif syscall == 'mmap':
            features.num_mmap += 1

        elif syscall == 'socket':
            features.num_socket += 1
            if record.family == 'ipv4' or record.family == 'ipv6':
                features.num_tcp_sockets += 1  # Simplified
            elif record.family == 'unix':
                features.num_unix_sockets += 1

        elif syscall == 'connect':
            features.num_connect += 1
            features.num_network_connects += 1
            if record.ip:
                ip_addresses.add(record.ip)
            if record.family == 'ipv4':
                features.has_ipv4_connect = True
            elif record.family == 'ipv6':
                features.has_ipv6_connect = True
            if record.port == 443:
                features.num_port_443_connects += 1

    features._thread_names = thread_names
    features._file_paths = file_paths
    features._ip_addresses = ip_addresses

    for thread_name in thread_names:
        if re.match(THREAD_PATTERNS["okhttp"], thread_name):
            features.has_okhttp_thread = True
        if re.match(THREAD_PATTERNS["okhttp_task"], thread_name):
            features.has_okhttp_task_thread = True

        if re.match(THREAD_PATTERNS["rxjava"], thread_name):
            features.has_rxjava_thread = True
        if re.match(THREAD_PATTERNS["rxjava_cached"], thread_name):
            features.has_rxjava_cached_thread = True

        if re.match(THREAD_PATTERNS["coroutines"], thread_name):
            features.has_coroutine_thread = True

        if re.match(THREAD_PATTERNS["workmanager"], thread_name):
            features.has_workmanager_thread = True
        if re.match(THREAD_PATTERNS["workmanager_alt"], thread_name):
            features.has_workmanager_alt_thread = True

        if re.match(THREAD_PATTERNS["room_io"], thread_name):
            features.has_room_io_thread = True

        if re.match(THREAD_PATTERNS["glide"], thread_name):
            features.has_glide_thread = True
        if re.match(THREAD_PATTERNS["glide_source"], thread_name):
            features.has_glide_source_thread = True
        if re.match(THREAD_PATTERNS["glide_disk"], thread_name):
            features.has_glide_disk_thread = True

        if re.match(THREAD_PATTERNS["coil"], thread_name):
            features.has_coil_thread = True

        if re.match(THREAD_PATTERNS["fresco"], thread_name):
            features.has_fresco_thread = True

        if re.match(THREAD_PATTERNS["exoplayer"], thread_name):
            features.has_exoplayer_thread = True
        if re.match(THREAD_PATTERNS["flutter"], thread_name):
            features.has_flutter_thread = True
        if re.match(THREAD_PATTERNS["async_task"], thread_name):
            features.has_async_task_thread = True

    for path in file_paths:
        if re.search(PATH_PATTERNS["room_wal"], path):
            features.has_room_wal = True
        if re.search(PATH_PATTERNS["room_shm"], path):
            features.has_room_shm = True
        if re.search(PATH_PATTERNS["room_journal"], path):
            features.has_room_journal = True

        if re.search(PATH_PATTERNS["workmanager_db"], path):
            features.has_workmanager_db = True

        if re.search(PATH_PATTERNS["datastore"], path):
            features.has_datastore = True

        if re.search(PATH_PATTERNS["okhttp_cache"], path):
            features.has_okhttp_cache = True
        if re.search(PATH_PATTERNS["okhttp_cache_dir"], path):
            features.has_okhttp_cache_dir = True
        if re.search(PATH_PATTERNS["okhttp_journal"], path):
            features.has_okhttp_journal = True

        if re.search(PATH_PATTERNS["glide_cache"], path):
            features.has_glide_cache = True
        if re.search(PATH_PATTERNS["glide_journal"], path):
            features.has_glide_journal = True

        if re.search(PATH_PATTERNS["coil_cache"], path):
            features.has_coil_cache = True
        if re.search(PATH_PATTERNS["coil_cache_v3"], path):
            features.has_coil_cache_v3 = True
        if re.search(PATH_PATTERNS["coil_journal"], path):
            features.has_coil_journal = True

        if re.search(PATH_PATTERNS["fresco_cache"], path):
            features.has_fresco_cache = True

        if re.search(PATH_PATTERNS["cacerts"], path):
            features.has_cacerts_access = True
        if re.search(PATH_PATTERNS["http_cache"], path):
            features.has_http_cache = True

        if re.search(PATH_PATTERNS["shared_prefs"], path):
            features.num_shared_prefs += 1
        if re.search(PATH_PATTERNS["native_lib"], path):
            features.num_native_libs += 1

    features.num_unique_threads = len(thread_names)
    features.num_databases = len(database_files)
    features.num_unique_ips = len(ip_addresses)

    features.trace_duration_sec = features.total_syscalls / 100.0  

    if features.trace_duration_sec > 0:
        features.syscalls_per_second = features.total_syscalls / features.trace_duration_sec
        features.threads_per_second = features.num_threads_spawned / features.trace_duration_sec

    return features


def features_to_dict(features: AppFeatures) -> Dict[str, Any]:
    result = {}

    for key, value in features.__dict__.items():
        if key.startswith('_'):
            continue

        if isinstance(value, bool):
            result[key] = 1 if value else 0
        else:
            result[key] = value

    return result


def get_feature_columns() -> List[str]:
    dummy = AppFeatures()
    columns = []

    for key in dummy.__dict__.keys():
        if not key.startswith('_'):
            columns.append(key)

    return columns


def process_trace_file(trace_path: str, package: str = "") -> AppFeatures:
    if not package:
        filename = os.path.basename(trace_path)
        package = filename.replace('.syscall.log', '').replace('.log', '')

    records = parse_syscall_log(trace_path)
    features = extract_features(records, package)

    return features


def process_all_traces(trace_dir: str, output_csv: str):
    trace_files = list(Path(trace_dir).glob('*.log'))

    if not trace_files:
        print(f"No trace files found in {trace_dir}")
        return

    print(f"Processing {len(trace_files)} trace files...")

    all_features = []

    for trace_path in sorted(trace_files):
        print(f"  Processing: {trace_path.name}")
        features = process_trace_file(str(trace_path))
        all_features.append(features_to_dict(features))

    columns = get_feature_columns()

    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(all_features)

    print(f"Total apps processed: {len(all_features)}")


def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    if sys.argv[1] == '--single':
        if len(sys.argv) < 3:
            print("Please provide a trace file path")
            sys.exit(1)

        trace_path = sys.argv[2]
        features = process_trace_file(trace_path)

        print("\nExtracted Features:")
        print("=" * 50)
        for key, value in features_to_dict(features).items():
            print(f"  {key}: {value}")

    else:
        trace_dir = sys.argv[1]
        output_csv = sys.argv[2] if len(sys.argv) > 2 else "features.csv"

        process_all_traces(trace_dir, output_csv)


if __name__ == "__main__":
    main()
