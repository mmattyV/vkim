# server.py
import os
import sys
import time
import argparse
import logging
import signal
import grpc
from concurrent import futures

# Add project root to path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Import gRPC service modules
import message_service_pb2
import message_service_pb2_grpc
import message_service_extensions_pb2
import message_service_extensions_pb2_grpc

# Import our implementation
from replication.replica_manager import ReplicaManager
from service.replicated_chat_service import ReplicatedChatServiceServicer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def serve(host='localhost', port=50051, replica_id=None, replica_port=None, 
          data_dir='./data', join_host=None, join_port=None):
    """Start the replicated chat server."""
    
    # Create replica manager with a separate port for replica communication
    if not replica_port:
        replica_port = port + 1000  # Default replica port is service port + 1000
        
    replica_manager = ReplicaManager(
        replica_id=replica_id,
        host=host,
        port=replica_port,
        data_dir=data_dir
    )
    
    # Start the replica manager
    replica_manager.start()
    
    # Join cluster if specified
    if join_host and join_port:
        try:
            # Create a channel to the existing replica
            join_channel = grpc.insecure_channel(f"{join_host}:{join_port}")
            join_stub = message_service_extensions_pb2_grpc.ReplicationServiceStub(join_channel)
            
            # Send join request
            request = message_service_extensions_pb2.JoinRequest(
                replica_id=replica_manager.replica_id,
                host=host,
                port=replica_port
            )
            
            response = join_stub.JoinCluster(request, timeout=5)
            if response.success:
                logger.info(f"Successfully joined the cluster: {response.message}")
            else:
                logger.warning(f"Failed to join cluster: {response.message}")
                
        except Exception as e:
            logger.error(f"Error joining cluster: {e}")
            logger.info("Continuing as a standalone replica...")
    
    # Create a gRPC server for client communication
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    
    # Add the replicated chat service
    chat_service = ReplicatedChatServiceServicer(replica_manager)
    message_service_pb2_grpc.add_ChatServiceServicer_to_server(chat_service, server)
    
    # Add secure/insecure port for client connections
    server_address = f"{host}:{port}"
    server.add_insecure_port(server_address)
    
    # Start the server
    server.start()
    logger.info(f"Server started at {server_address}")
    logger.info(f"Replica ID: {replica_manager.replica_id}")
    logger.info(f"Replica Port: {replica_port}")
    logger.info(f"Data Directory: {os.path.abspath(data_dir)}")
    
    # Handle graceful shutdown
    def shutdown(signum, frame):
        logger.info("Shutting down server...")
        server.stop(5)  # 5 second grace period
        replica_manager.stop()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    # Keep server running
    try:
        while True:
            time.sleep(60)  # Check every minute
            # Report status
            logger.info(f"Server status: Replica role={replica_manager.state}, " +
                       f"Leader={replica_manager.leader_id or 'None'}, " +
                       f"Term={replica_manager.current_term}")
    except KeyboardInterrupt:
        shutdown(None, None)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replicated Chat Server")
    parser.add_argument("--host", type=str, default="localhost", help="Host to bind to")
    parser.add_argument("--port", type=int, default=50051, help="Port for client connections")
    parser.add_argument("--replica-id", type=str, default=None, help="Unique ID for this replica")
    parser.add_argument("--replica-port", type=int, default=None, help="Port for replica communication")
    parser.add_argument("--data-dir", type=str, default="./data", help="Directory for data storage")
    parser.add_argument("--join-host", type=str, default=None, help="Host of existing replica to join")
    parser.add_argument("--join-port", type=int, default=None, help="Port of existing replica to join")
    
    args = parser.parse_args()
    
    serve(
        host=args.host,
        port=args.port,
        replica_id=args.replica_id,
        replica_port=args.replica_port,
        data_dir=args.data_dir,
        join_host=args.join_host,
        join_port=args.join_port
    )