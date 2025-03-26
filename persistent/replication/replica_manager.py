# replication/replica_manager.py
import os
import sys
import time
import threading
import json
import random
import logging
import grpc
from concurrent import futures
import socket
import uuid

# Add parent directory to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import database module
from storage.db_storage import ChatDatabase

# Import extended message service protos
import message_service_extensions_pb2
import message_service_extensions_pb2_grpc

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReplicationState:
    """Constants for replication state"""
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"

class ReplicaManager:
    """
    Manages replication, leader election, and fault tolerance for the chat service.
    Implements a simplified Raft consensus algorithm for leader election.
    """
    def __init__(self, replica_id=None, host='localhost', port=50052, 
                 data_dir='./data', leader_timeout=5, heartbeat_interval=1):
        """Initialize the replica manager."""
        # Generate a unique ID if not provided
        self.replica_id = replica_id or f"replica-{uuid.uuid4().hex[:8]}"
        self.host = host
        self.port = port
        self.data_dir = data_dir
        
        # Ensure data directory exists
        os.makedirs(data_dir, exist_ok=True)
        
        # Initialize the database
        db_path = os.path.join(data_dir, f"{self.replica_id}.db")
        self.db = ChatDatabase(db_path)
        
        # State variables
        self.state = ReplicationState.FOLLOWER
        self.current_term = 0
        self.voted_for = None
        self.leader_id = None
        self.last_heartbeat = 0
        self.commit_index = 0
        self.last_applied = 0
        
        # Load state from database if available
        self.load_state()
        
        # Configuration
        self.leader_timeout = leader_timeout  # seconds
        self.heartbeat_interval = heartbeat_interval  # seconds
        
        # Known replicas (including self)
        self.replicas = {}
        self.replicas[self.replica_id] = {
            'host': self.host, 
            'port': self.port,
            'is_alive': True,
            'last_heartbeat': time.time()
        }
        
        # Load cluster configuration if available
        self.load_cluster_config()
        
        # gRPC server and stubs
        self.server = None
        self.stubs = {}  # Cached gRPC stubs for other replicas
        
        # Locks for thread safety
        self.state_lock = threading.Lock()
        self.replicas_lock = threading.Lock()
        
        # Background threads
        self.election_thread = None
        self.heartbeat_thread = None
        self.running = False
        
        logger.info(f"Initialized replica {self.replica_id} at {host}:{port}")
        
    def load_state(self):
        """Load state variables from the database."""
        with self.state_lock:
            self.current_term = int(self.db.get_system_state('current_term', '0'))
            self.voted_for = self.db.get_system_state('voted_for')
            self.leader_id = self.db.get_system_state('leader_id')
            self.commit_index = int(self.db.get_system_state('commit_index', '0'))
            self.last_applied = int(self.db.get_system_state('last_applied', '0'))
            
            # Update last_applied from database if necessary
            db_last_applied = self.db.get_last_applied_operation_id()
            if db_last_applied > self.last_applied:
                self.last_applied = db_last_applied
                
    def save_state(self):
        """Save state variables to the database."""
        with self.state_lock:
            self.db.set_system_state('current_term', str(self.current_term))
            self.db.set_system_state('voted_for', self.voted_for if self.voted_for else '')
            self.db.set_system_state('leader_id', self.leader_id if self.leader_id else '')
            self.db.set_system_state('commit_index', str(self.commit_index))
            self.db.set_system_state('last_applied', str(self.last_applied))
            
    def load_cluster_config(self):
        """Load cluster configuration from the database."""
        with self.replicas_lock:
            config_str = self.db.get_system_state('cluster_config')
            if config_str:
                try:
                    config = json.loads(config_str)
                    self.replicas.update(config)
                except json.JSONDecodeError:
                    logger.error("Failed to parse cluster configuration")
                    
    def save_cluster_config(self):
        """Save cluster configuration to the database."""
        with self.replicas_lock:
            config_str = json.dumps(self.replicas)
            self.db.set_system_state('cluster_config', config_str)
            
    def start(self):
        """Start the replica manager and gRPC server."""
        if self.running:
            return
            
        self.running = True
        
        # Start gRPC server
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        message_service_extensions_pb2_grpc.add_ReplicationServiceServicer_to_server(
            ReplicationServicer(self), self.server
        )
        
        # Add secure/insecure port
        self.server.add_insecure_port(f'{self.host}:{self.port}')
        self.server.start()
        logger.info(f"Started gRPC server at {self.host}:{self.port}")
        
        # Start background threads
        self.start_election_timer()
        self.start_heartbeat_timer()
        
        logger.info(f"Replica {self.replica_id} is running as {self.state}")
        
    def stop(self):
        """Stop the replica manager and gRPC server."""
        if not self.running:
            return
            
        self.running = False
        
        # Stop the server
        if self.server:
            self.server.stop(0)
            
        # Wait for threads to terminate
        if self.election_thread and self.election_thread.is_alive():
            self.election_thread.join(timeout=2)
            
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=2)
            
        # Save final state
        self.save_state()
        self.save_cluster_config()
        
        logger.info(f"Replica {self.replica_id} is stopped")
        
    def start_election_timer(self):
        """Start the election timer thread."""
        def election_timer():
            while self.running:
                if self.state != ReplicationState.LEADER:
                    time_since_heartbeat = time.time() - self.last_heartbeat
                    
                    # Randomize the election timeout to avoid split votes
                    timeout = self.leader_timeout + random.uniform(0, self.leader_timeout)
                    
                    if time_since_heartbeat > timeout:
                        self.start_election()
                        
                time.sleep(1)  # Check every second
                
        self.election_thread = threading.Thread(target=election_timer, daemon=True)
        self.election_thread.start()
        
    def start_heartbeat_timer(self):
        """Start the heartbeat timer thread."""
        def heartbeat_timer():
            while self.running:
                if self.state == ReplicationState.LEADER:
                    self.send_heartbeat()
                time.sleep(self.heartbeat_interval)
                
        self.heartbeat_thread = threading.Thread(target=heartbeat_timer, daemon=True)
        self.heartbeat_thread.start()
        
    def start_election(self):
        """Start a leader election as a candidate."""
        with self.state_lock:
            # Increment current term and vote for self
            self.current_term += 1
            self.voted_for = self.replica_id
            self.state = ReplicationState.CANDIDATE
            self.save_state()
            
            logger.info(f"Starting election for term {self.current_term}")
            
            # Prepare vote request
            request = message_service_extensions_pb2.VoteRequest(
                candidate_id=self.replica_id,
                term=self.current_term,
                last_log_index=self.last_applied,
                last_log_term=self.current_term - 1  # Simplification
            )
            
            # Send vote requests to all other replicas
            votes_received = 1  # Vote for self
            votes_needed = (len(self.replicas) // 2) + 1
            
            replicas_copy = {}
            with self.replicas_lock:
                replicas_copy = self.replicas.copy()
                
            for replica_id, info in replicas_copy.items():
                if replica_id == self.replica_id:
                    continue  # Skip self
                    
                if not info.get('is_alive', False):
                    continue  # Skip known dead replicas
                    
                try:
                    stub = self.get_stub(replica_id)
                    response = stub.RequestVote(request, timeout=2)
                    
                    logger.info(f"Vote response from {replica_id}: {response.vote_granted}")
                    
                    # If responder has higher term, become follower
                    if response.term > self.current_term:
                        with self.state_lock:
                            self.current_term = response.term
                            self.state = ReplicationState.FOLLOWER
                            self.voted_for = None
                            self.save_state()
                        return
                        
                    # Count votes
                    if response.vote_granted:
                        votes_received += 1
                        
                except Exception as e:
                    logger.error(f"Failed to request vote from {replica_id}: {e}")
                    # Mark replica as potentially dead
                    with self.replicas_lock:
                        if replica_id in self.replicas:
                            self.replicas[replica_id]['is_alive'] = False
                            
            # Check if we won the election
            if votes_received >= votes_needed and self.state == ReplicationState.CANDIDATE:
                logger.info(f"Won election for term {self.current_term} with {votes_received} votes")
                self.become_leader()
            else:
                logger.info(f"Lost election for term {self.current_term}, got {votes_received} of {votes_needed} votes needed")
                # Return to follower state
                with self.state_lock:
                    self.state = ReplicationState.FOLLOWER
                    self.save_state()
                    
    def become_leader(self):
        """Transition to leader state."""
        with self.state_lock:
            if self.state != ReplicationState.CANDIDATE:
                return
                
            self.state = ReplicationState.LEADER
            self.leader_id = self.replica_id
            self.save_state()
            
            logger.info(f"Became leader for term {self.current_term}")
            
            # Send initial heartbeat to establish authority
            self.send_heartbeat()
            
    def send_heartbeat(self):
        """Send heartbeat to all replicas."""
        with self.state_lock:
            if self.state != ReplicationState.LEADER:
                return
                
            # Get operations to replicate (limited to avoid overwhelming followers)
            operations = []
            try:
                # Prepare operations from last commit index
                db_operations = self.db.get_unapplied_operations(limit=100)
                for op in db_operations:
                    operations.append(message_service_extensions_pb2.Operation(
                        log_id=op['log_id'],
                        operation_type=op['operation'],
                        parameters=op['parameters'],
                        timestamp=op['timestamp']
                    ))
            except Exception as e:
                logger.error(f"Error preparing operations for heartbeat: {e}")
                
            # Prepare heartbeat request
            request = message_service_extensions_pb2.HeartbeatRequest(
                leader_id=self.replica_id,
                term=self.current_term,
                commit_index=self.commit_index,
                operations=operations
            )
            
            # Send heartbeat to all replicas
            replicas_copy = {}
            with self.replicas_lock:
                replicas_copy = self.replicas.copy()
                
            for replica_id, info in replicas_copy.items():
                if replica_id == self.replica_id:
                    continue  # Skip self
                    
                try:
                    stub = self.get_stub(replica_id)
                    response = stub.SendHeartbeat(request, timeout=2)
                    
                    # Update replica status
                    with self.replicas_lock:
                        if replica_id in self.replicas:
                            self.replicas[replica_id]['is_alive'] = True
                            self.replicas[replica_id]['last_heartbeat'] = time.time()
                            
                    # If responder has higher term, become follower
                    if response.term > self.current_term:
                        with self.state_lock:
                            self.current_term = response.term
                            self.state = ReplicationState.FOLLOWER
                            self.voted_for = None
                            self.leader_id = None
                            self.save_state()
                        return
                        
                    logger.debug(f"Heartbeat acknowledged by {replica_id}, last applied: {response.last_applied_index}")
                    
                except Exception as e:
                    logger.error(f"Failed to send heartbeat to {replica_id}: {e}")
                    # Mark replica as potentially dead
                    with self.replicas_lock:
                        if replica_id in self.replicas:
                            self.replicas[replica_id]['is_alive'] = False
                            
            self.save_cluster_config()
            
    def receive_heartbeat(self, leader_id, term, commit_index, operations):
        """Process heartbeat from the leader."""
        with self.state_lock:
            # If term is outdated, reject
            if term < self.current_term:
                return False, self.current_term, self.last_applied, "Term is outdated"
                
            # If term is newer, update term and become follower
            if term > self.current_term:
                self.current_term = term
                self.state = ReplicationState.FOLLOWER
                self.voted_for = None
                
            # Always update leader and heartbeat time
            self.leader_id = leader_id
            self.last_heartbeat = time.time()
            
            # Process operations
            if operations:
                self.apply_operations(operations, commit_index)
                
            self.save_state()
            return True, self.current_term, self.last_applied, "Heartbeat acknowledged"
            
    def apply_operations(self, operations, leader_commit_index):
        """Apply operations from the leader."""
        if not operations:
            return
            
        operation_ids = []
        for op in operations:
            if op.log_id > self.last_applied:
                try:
                    # Apply the operation based on its type
                    self.apply_operation(op)
                    operation_ids.append(op.log_id)
                    self.last_applied = max(self.last_applied, op.log_id)
                except Exception as e:
                    logger.error(f"Failed to apply operation {op.log_id}: {e}")
                    
        # Mark operations as applied
        if operation_ids:
            self.db.mark_operations_applied(operation_ids)
            
        # Update commit index if leader's is higher
        if leader_commit_index > self.commit_index:
            self.commit_index = min(leader_commit_index, self.last_applied)
    
    def apply_operation(self, operation):
        """Apply a single operation based on its type."""
        op_type = operation.operation_type
        params = json.loads(operation.parameters)
        
        if op_type == "create_user":
            self.db.create_user(params['username'], params['hashed_password'])
        elif op_type == "delete_user":
            self.db.delete_user(params['username'])
        elif op_type == "queue_message":
            self.db.queue_message(params['sender'], params['recipient'], params['content'])
        elif op_type == "mark_messages_read":
            # This is a simplified implementation; you might need to adapt it
            user = params['username']
            count = params['count']
            self.db.get_unread_messages(user, count)  # This marks them as read
        elif op_type == "delete_messages":
            self.db.delete_read_messages(params['username'], params['delete_info'])
        elif op_type == "system_state":
            self.db.set_system_state(params['key'], params['value'])
        else:
            logger.warning(f"Unknown operation type: {op_type}")
            
    def get_stub(self, replica_id):
        """Get or create a gRPC stub for a replica."""
        if replica_id not in self.stubs:
            with self.replicas_lock:
                if replica_id not in self.replicas:
                    raise ValueError(f"Unknown replica: {replica_id}")
                
                info = self.replicas[replica_id]
                channel = grpc.insecure_channel(f"{info['host']}:{info['port']}")
                self.stubs[replica_id] = message_service_extensions_pb2_grpc.ReplicationServiceStub(channel)
                
        return self.stubs[replica_id]
        
    def log_operation(self, operation_type, **params):
        """Log an operation to be replicated to followers."""
        if self.state != ReplicationState.LEADER:
            logger.warning("Attempted to log operation while not the leader")
            return None
            
        # Convert parameters to JSON string
        params_json = json.dumps(params)
        
        # Add to the log
        log_id = self.db.log_operation(operation_type, params_json)
        
        # Update commit index
        self.commit_index = log_id
        
        return log_id
        
    def handle_client_operation(self, operation_type, **params):
        """Handle a client operation based on the current state."""
        with self.state_lock:
            # If we're the leader, process the operation
            if self.state == ReplicationState.LEADER:
                return self.log_operation(operation_type, **params)
                
            # If we're not the leader, redirect to the leader if known
            if self.leader_id and self.leader_id != self.replica_id:
                with self.replicas_lock:
                    if self.leader_id in self.replicas:
                        leader_info = self.replicas[self.leader_id]
                        return {
                            "redirect": True,
                            "leader_host": leader_info['host'],
                            "leader_port": leader_info['port'],
                            "leader_id": self.leader_id
                        }
                        
            # No known leader
            return {
                "error": True,
                "message": "No leader available, try again later"
            }
            
# replication/replica_manager.py (continued)
class ReplicationServicer(message_service_extensions_pb2_grpc.ReplicationServiceServicer):
    """
    gRPC servicer for the replication service.
    Handles leader election and state synchronization.
    """
    def __init__(self, replica_manager):
        self.manager = replica_manager
        
    def RequestVote(self, request, context):
        """Handle a request for vote from a candidate."""
        candidate_id = request.candidate_id
        term = request.term
        
        with self.manager.state_lock:
            # If our term is higher, reject the vote
            if term < self.manager.current_term:
                return message_service_extensions_pb2.VoteResponse(
                    vote_granted=False,
                    term=self.manager.current_term,
                    message="Term is outdated"
                )
                
            # If term is newer, update our term
            if term > self.manager.current_term:
                self.manager.current_term = term
                self.manager.voted_for = None
                self.manager.state = ReplicationState.FOLLOWER
                
            # Check if we can vote for this candidate
            can_vote = (self.manager.voted_for is None or 
                       self.manager.voted_for == candidate_id)
            
            # Check if candidate's log is at least as up-to-date as ours
            log_ok = (request.last_log_term > self.manager.current_term or
                     (request.last_log_term == self.manager.current_term and
                      request.last_log_index >= self.manager.last_applied))
            
            vote_granted = can_vote and log_ok
            
            if vote_granted:
                self.manager.voted_for = candidate_id
                self.manager.save_state()
                
            return message_service_extensions_pb2.VoteResponse(
                vote_granted=vote_granted,
                term=self.manager.current_term,
                message="Vote granted" if vote_granted else "Vote denied"
            )
            
    def SendHeartbeat(self, request, context):
        """Handle a heartbeat from the leader."""
        leader_id = request.leader_id
        term = request.term
        commit_index = request.commit_index
        operations = request.operations
        
        success, term, last_applied, message = self.manager.receive_heartbeat(
            leader_id, term, commit_index, operations
        )
        
        return message_service_extensions_pb2.HeartbeatResponse(
            success=success,
            term=term,
            last_applied_index=last_applied,
            message=message
        )
        
    def TransferLeadership(self, request, context):
        """Handle a leadership transfer request."""
        new_leader_id = request.new_leader_id
        term = request.term
        
        with self.manager.state_lock:
            # Only the current leader can transfer leadership
            if self.manager.state != ReplicationState.LEADER:
                return message_service_extensions_pb2.StatusResponse(
                    success=False,
                    message="Not the leader"
                )
                
            # Check if term matches
            if term != self.manager.current_term:
                return message_service_extensions_pb2.StatusResponse(
                    success=False,
                    message="Term mismatch"
                )
                
            # Check if new leader exists
            with self.manager.replicas_lock:
                if new_leader_id not in self.manager.replicas:
                    return message_service_extensions_pb2.StatusResponse(
                        success=False,
                        message="New leader not in cluster"
                    )
                    
                if not self.manager.replicas[new_leader_id].get('is_alive', False):
                    return message_service_extensions_pb2.StatusResponse(
                        success=False,
                        message="New leader is not alive"
                    )
                    
            # Step down as leader
            self.manager.state = ReplicationState.FOLLOWER
            self.manager.leader_id = new_leader_id
            self.manager.save_state()
            
            return message_service_extensions_pb2.StatusResponse(
                success=True,
                message=f"Leadership transferred to {new_leader_id}"
            )
            
    def SyncOperations(self, request, context):
        """Handle a request for operation synchronization."""
        replica_id = request.replica_id
        last_applied_index = request.last_applied_index
        max_operations = request.max_operations
        
        # Only the leader should handle sync requests
        with self.manager.state_lock:
            if self.manager.state != ReplicationState.LEADER:
                return message_service_extensions_pb2.SyncResponse(
                    success=False,
                    message="Not the leader",
                    operations=[],
                    leader_commit_index=self.manager.commit_index
                )
                
            try:
                # Get operations after last_applied_index
                operations = []
                db_operations = self.manager.db.get_unapplied_operations(limit=max_operations)
                
                for op in db_operations:
                    if op['log_id'] > last_applied_index:
                        operations.append(message_service_extensions_pb2.Operation(
                            log_id=op['log_id'],
                            operation_type=op['operation'],
                            parameters=op['parameters'],
                            timestamp=op['timestamp']
                        ))
                        
                return message_service_extensions_pb2.SyncResponse(
                    success=True,
                    message=f"Sending {len(operations)} operations",
                    operations=operations,
                    leader_commit_index=self.manager.commit_index
                )
                
            except Exception as e:
                logger.error(f"Error handling sync request: {e}")
                return message_service_extensions_pb2.SyncResponse(
                    success=False,
                    message=f"Error: {str(e)}",
                    operations=[],
                    leader_commit_index=self.manager.commit_index
                )
                
    def GetState(self, request, context):
        """Handle a request for full state transfer."""
        replica_id = request.replica_id
        
        # Only the leader should handle state transfer
        with self.manager.state_lock:
            if self.manager.state != ReplicationState.LEADER:
                return message_service_extensions_pb2.StateResponse(
                    success=False,
                    message="Not the leader",
                    state_data=b''
                )
                
            try:
                # This is a simplified approach - in a real system you would
                # implement incremental state transfer or snapshot replication
                
                # For now, just indicate success but don't actually transfer state
                return message_service_extensions_pb2.StateResponse(
                    success=True,
                    message="State transfer not implemented",
                    state_data=b''
                )
                
            except Exception as e:
                logger.error(f"Error handling state transfer: {e}")
                return message_service_extensions_pb2.StateResponse(
                    success=False,
                    message=f"Error: {str(e)}",
                    state_data=b''
                )
                
    def JoinCluster(self, request, context):
        """Handle a request to join the cluster."""
        replica_id = request.replica_id
        host = request.host
        port = request.port
        
        with self.manager.replicas_lock:
            # Add the new replica
            self.manager.replicas[replica_id] = {
                'host': host,
                'port': port,
                'is_alive': True,
                'last_heartbeat': time.time()
            }
            
            # Save updated configuration
            self.manager.save_cluster_config()
            
        return message_service_extensions_pb2.StatusResponse(
            success=True,
            message=f"Added replica {replica_id} to cluster"
        )
        
    def LeaveCluster(self, request, context):
        """Handle a request to leave the cluster."""
        replica_id = request.replica_id
        
        with self.manager.replicas_lock:
            if replica_id in self.manager.replicas:
                del self.manager.replicas[replica_id]
                
                # Save updated configuration
                self.manager.save_cluster_config()
                
                return message_service_extensions_pb2.StatusResponse(
                    success=True,
                    message=f"Removed replica {replica_id} from cluster"
                )
            else:
                return message_service_extensions_pb2.StatusResponse(
                    success=False,
                    message=f"Replica {replica_id} not in cluster"
                )
                
    def GetClusterInfo(self, request, context):
        """Handle a request for cluster information."""
        replica_id = request.replica_id
        
        with self.manager.state_lock, self.manager.replicas_lock:
            # Convert replicas to protocol buffer format
            replicas_info = []
            for r_id, info in self.manager.replicas.items():
                replicas_info.append(message_service_extensions_pb2.ReplicaInfo(
                    replica_id=r_id,
                    host=info['host'],
                    port=info['port'],
                    is_alive=info.get('is_alive', False),
                    last_heartbeat=int(info.get('last_heartbeat', 0))
                ))
                
            return message_service_extensions_pb2.ClusterInfoResponse(
                success=True,
                message="Cluster info",
                leader_id=self.manager.leader_id or "",
                current_term=self.manager.current_term,
                replicas=replicas_info
            )
            