# server.py
import os
import sys
import time
import argparse
import logging
import signal
import threading
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

def test_replica_communication(replica_manager):
    """Test communication between replicas"""
    with replica_manager.replicas_lock:
        replicas = replica_manager.replicas.copy()
    
    for replica_id, info in replicas.items():
        if replica_id == replica_manager.replica_id:
            continue  # Skip self
        
        logger.info(f"Testing communication with {replica_id} at {info['host']}:{info['port']}")
        try:
            channel = grpc.insecure_channel(f"{info['host']}:{info['port']}")
            stub = message_service_extensions_pb2_grpc.ReplicationServiceStub(channel)
            
            # Create a simple request just to test connectivity
            request = message_service_extensions_pb2.ClusterInfoRequest(
                replica_id=replica_manager.replica_id
            )
            
            # Try to get cluster info with a timeout
            response = stub.GetClusterInfo(request, timeout=3)
            logger.info(f"Successfully communicated with {replica_id}")
            
        except Exception as e:
            logger.error(f"Failed to communicate with {replica_id}: {e}")

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
    
    # Force an election attempt if this is the first replica
    if not join_host and not join_port:
        logger.info("First replica - initiating election in 5 seconds...")
        def delayed_election():
            time.sleep(5)
            logger.info("Triggering election...")
            replica_manager.start_election()
        
        threading.Thread(target=delayed_election, daemon=True).start()
    
    # Modified join section in server.py
    if join_host and join_port:
        logger.info(f"Attempting to join cluster at {join_host}:{join_port}...")
        
        max_retries = 3
        for retry in range(max_retries):
            try:
                # Create a channel with a shorter timeout
                join_channel = grpc.insecure_channel(f"{join_host}:{join_port}")
                join_stub = message_service_extensions_pb2_grpc.ReplicationServiceStub(join_channel)
                
                # Simple ping to test basic connectivity
                logger.info("Testing basic connectivity...")
                
                # Prepare join request
                request = message_service_extensions_pb2.JoinRequest(
                    replica_id=replica_manager.replica_id,
                    host=host,
                    port=replica_port
                )
                
                # Try with an even shorter timeout first
                logger.info(f"Sending JoinCluster request (attempt {retry+1}/{max_retries})...")
                response = join_stub.JoinCluster(request, timeout=5)
                
                if response.success:
                    logger.info(f"Successfully joined the cluster: {response.message}")
                    # Test communication with other replicas after joining
                    threading.Thread(target=lambda: test_replica_communication(replica_manager), daemon=True).start()
                    break
                else:
                    logger.warning(f"Failed to join cluster: {response.message}")
                    
            except grpc.RpcError as e:
                logger.error(f"gRPC error joining cluster (attempt {retry+1}): {e.code()}: {e.details()}")
                time.sleep(1)  # Wait before retrying
            except Exception as e:
                logger.error(f"Error joining cluster: {e}")
                break
        else:
            logger.info("Failed all attempts to join cluster. Continuing as a standalone replica...")
            
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