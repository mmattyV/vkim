# server.py

import argparse
import logging
import sys
import time
import grpc
from concurrent import futures

from replication.primary_backup_manager import PrimaryBackupManager, Role
from storage.db_storage import ChatDatabase
from service.replicated_chat_service import ReplicatedChatServiceServicer
import message_service_pb2_grpc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def serve(host="localhost", port=50051, replica_id="replica1", 
          replica_port=51051, known_replicas=None, is_primary=False, data_dir="./data"):
    """
    Simplified primary-backup server entry point.
    """
    # 1. Initialize DB
    db_path = f"{data_dir}/{replica_id}.db"
    db = ChatDatabase(db_path)
    
    # 2. Start the primary-backup manager
    pb_manager = PrimaryBackupManager(
        db=db,
        replica_id=replica_id,
        host=host,
        port=replica_port,
        known_replicas=known_replicas or {},
        is_primary=is_primary
    )
    pb_manager.start()
    
    # 3. Start gRPC server for client (ChatService)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    
    # ChatService that references the primary-backup manager
    chat_service = ReplicatedChatServiceServicer(db, pb_manager)
    message_service_pb2_grpc.add_ChatServiceServicer_to_server(chat_service, server)
    
    server.add_insecure_port(f"{host}:{port}")
    server.start()
    
    logger.info(f"Chat server started on {host}:{port} as {replica_id}, role={pb_manager.role}")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down servers...")
        server.stop(5)
        pb_manager.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=50051)
    parser.add_argument("--replica-id", default="replica1")
    parser.add_argument("--replica-port", type=int, default=51051)
    parser.add_argument("--primary", action="store_true", help="Start this node as primary")
    parser.add_argument("--data-dir", default="./data")
    # known replicas can be a simple JSON or repeated flags
    parser.add_argument("--known-replicas", nargs="*", default=[], help="List of host:port,... for backups")
    args = parser.parse_args()
    
    # Convert known_replicas to a dict if needed
    known_dict = {}
    # Example usage: --known-replicas replica2=localhost:51052 replica3=localhost:51053
    for item in args.known_replicas:
        rep_id, address = item.split("=")
        host_port = address.split(":")
        known_dict[rep_id] = (host_port[0], int(host_port[1]))
    
    serve(
        host=args.host,
        port=args.port,
        replica_id=args.replica_id,
        replica_port=args.replica_port,
        known_replicas=known_dict,
        is_primary=args.primary,
        data_dir=args.data_dir
    )
