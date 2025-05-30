# replication/primary_backup_manager.py

import time
import threading
import logging
import grpc
import json
from concurrent import futures

import message_service_extensions_pb2
import message_service_extensions_pb2_grpc
import message_service_pb2  # Import the module that defines StatusResponse

logger = logging.getLogger(__name__)

class Role:
    PRIMARY = "primary"
    BACKUP = "backup"

class PrimaryBackupManager(message_service_extensions_pb2_grpc.ReplicationServiceServicer):
    """
    A simplified manager that handles primary–backup replication via direct state pushes.
    The 'primary' handles all writes; the backups receive updates from the primary.
    If the primary fails, a backup can promote itself to become the new primary.
    """
    def __init__(self, db, replica_id, host, port, known_replicas, is_primary=False):
        """
        :param db: ChatDatabase instance.
        :param replica_id: Unique ID for this replica.
        :param host: Host/IP for the replication gRPC server.
        :param port: Port for the replication gRPC server.
        :param known_replicas: Dict of other replicas {replica_id: (host, port)}.
        :param is_primary: Boolean flag to set this replica as primary.
        """
        self.db = db
        self.replica_id = replica_id
        self.host = host
        self.port = port
        self.known_replicas = known_replicas or {}
        self.role = Role.PRIMARY if is_primary else Role.BACKUP

        if self.role == Role.BACKUP:
            # Assume the primary is the first known replica
            for rep_id, (r_host, r_port) in self.known_replicas.items():
                self.primary_id = rep_id
                self.primary_host = r_host
                self.primary_port = r_port
                break
            else:
                self.primary_id = None
                self.primary_host = None
                self.primary_port = None
        else:
            self.primary_id = self.replica_id
            self.primary_host = self.host
            self.primary_port = self.port

        self.primary_check_interval = 3.0  # seconds
        self.server = None
        self.is_running = False
        self.stub_cache = {}
        
    def start(self):
        """
        Start the gRPC server for replication and, if backup, start monitoring the primary.
        """
        self.is_running = True
        
        # 1. Start the gRPC server so we can receive updates (if we’re a backup)
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=5))
        message_service_extensions_pb2_grpc.add_ReplicationServiceServicer_to_server(self, self.server)
        
        self.server.add_insecure_port(f"{self.host}:{self.port}")
        self.server.start()
        
        logger.info(f"PrimaryBackupManager started at {self.host}:{self.port} as {self.role}")
        
        # 2. If we are primary, prepare stubs to backups
        if self.role == Role.PRIMARY:
            self.primary_id = self.replica_id
            self.primary_host = self.host
            self.primary_port = self.port
            self._initialize_stub_cache()
        else:
            # If backup, start a thread to monitor the primary
            monitor_thread = threading.Thread(target=self._monitor_primary, daemon=True)
            monitor_thread.start()
        
    def stop(self):
        """
        Stop the replication server and any background tasks.
        """
        self.is_running = False
        if self.server:
            self.server.stop(0)
            logger.info(f"Replication server for {self.replica_id} stopped.")
        
    def _initialize_stub_cache(self):
        """
        For the primary: create gRPC stubs to each backup for pushing updates.
        """
        for r_id, (r_host, r_port) in self.known_replicas.items():
            # Don’t create a stub to ourselves
            if r_id == self.replica_id:
                continue
            channel = grpc.insecure_channel(f"{r_host}:{r_port}")
            stub = message_service_extensions_pb2_grpc.ReplicationServiceStub(channel)
            self.stub_cache[r_id] = stub
        
        logger.info(f"Stub cache initialized for primary {self.replica_id}. Known replicas: {list(self.stub_cache.keys())}")
        
    def _monitor_primary(self):
        """
        Background thread (for backups) that periodically checks if the primary is alive.
        If the current primary fails, update primary info to the lowest candidate among known replicas.
        Only the backup with the lowest replica_id will eventually promote itself.
        """
        while self.is_running and self.role == Role.BACKUP:
            # If primary info is not set, try to select one from known_replicas.
            if not self.primary_id:
                if self.known_replicas:
                    candidate_id = min(self.known_replicas.keys())
                    self.primary_id = candidate_id
                    self.primary_host, self.primary_port = self.known_replicas[candidate_id]
                    logger.info(f"Primary info set to {self.primary_id} from known replicas.")
                else:
                    time.sleep(self.primary_check_interval)
                    continue

            try:
                # Try to ping the current primary.
                channel = grpc.insecure_channel(f"{self.primary_host}:{self.primary_port}")
                stub = message_service_extensions_pb2_grpc.ReplicationServiceStub(channel)
                request = message_service_extensions_pb2.ClusterInfoRequest(replica_id=self.replica_id)
                response = stub.GetClusterInfo(request, timeout=2)
                # If the ping succeeds and the response contains a leader_id, update our primary info.
                if response.leader_id and response.leader_id != self.primary_id:
                    if response.leader_id in self.known_replicas:
                        self.primary_id = response.leader_id
                        self.primary_host, self.primary_port = self.known_replicas[response.leader_id]
                        logger.info(f"Updated primary info to {self.primary_id} based on response.")
                # If we got a response, the primary is alive—sleep and continue.
            except Exception as e:
                logger.warning(f"Primary {self.primary_id} not responding; removing it from known replicas.")
                # Remove the unresponsive primary.
                if self.primary_id in self.known_replicas:
                    del self.known_replicas[self.primary_id]
                # Now, if there are any known replicas, select the new candidate.
                if self.known_replicas:
                    candidate_ids = list(self.known_replicas.keys()) + [self.replica_id]
                    lowest_candidate = min(candidate_ids)
                    if self.replica_id == lowest_candidate:
                        logger.warning(f"My replica_id {self.replica_id} is lowest among candidates; promoting self to PRIMARY...")
                        self.become_primary()
                        break
                    else:
                        new_primary = min(self.known_replicas.keys())
                        self.primary_id = new_primary
                        self.primary_host, self.primary_port = self.known_replicas[new_primary]
                        logger.info(f"Updated primary info to {self.primary_id}; waiting for it to respond.")
                else:
                    logger.warning("No known replicas available to update primary info.")
            time.sleep(self.primary_check_interval)

        
    def become_primary(self):
        """
        Promote this backup to primary role.
        """
        self.role = Role.PRIMARY
        self.primary_id = self.replica_id
        self.primary_host = self.host
        self.primary_port = self.port
        
        # Re-init stubs so we can push updates to other backups
        self._initialize_stub_cache()
        logger.info(f"{self.replica_id} is now PRIMARY.")
        
    # -------------------------------------------------------------------------
    #  gRPC methods: Called by the primary to push updates, or by clients checking cluster info
    # -------------------------------------------------------------------------
    
    def PushUpdate(self, request, context):
        """
        Backups receive direct updates from the primary here.
        Example: create_user, delete_user, queue_message, etc.
        """
        if self.role != Role.BACKUP:
            logger.warning(f"Received PushUpdate on a PRIMARY node ({self.replica_id}). Ignoring.")
            return message_service_pb2.StatusResponse(
                success=False,
                message="PushUpdate ignored by primary"
            )
        
        update_type = request.update_type
        params = dict(request.parameters)  # map<string,string> -> Python dict
        
        logger.info(f"Backup {self.replica_id} received update: {update_type} with params: {params}")
        
        # Apply to local DB
        if update_type == "create_user":
            self.db.create_user(params["username"], params["hashed_password"])
        elif update_type == "delete_user":
            # Force deletion on backups so that any lingering account is removed.
            self.db.force_delete_user(params["username"])
        elif update_type == "queue_message":
            self.db.queue_message(params["sender"], params["recipient"], params["content"])
        elif update_type == "mark_messages_read":
            # Expecting a JSON-encoded list of message IDs.
            message_ids = json.loads(params["message_ids"])
            self.db.mark_messages_as_read(message_ids)
        # Add other update types as needed...
        
        return message_service_pb2.StatusResponse(
            success=True,
            message="Update applied on backup"
        )
        
    def GetClusterInfo(self, request, context):
        """
        Basic call to check if we’re alive and to return the cluster info (including who is primary).
        """
        leader_id = self.primary_id if self.primary_id else ""
        return message_service_extensions_pb2.ClusterInfoResponse(
            success=True,
            message=f"Replica {self.replica_id} is alive (role={self.role})",
            leader_id=leader_id,
            current_term=0,  # Not used in primary-backup, but must return something
            replicas=[]
        )
        
    # -------------------------------------------------------------------------
    #  Helper for the primary to replicate updates to backups
    # -------------------------------------------------------------------------
    
    def push_update_to_backups(self, update_type, parameters):
        """
        Called by the PRIMARY whenever a write operation occurs (e.g. CreateAccount).
        We push the update to all backups in our stub cache.
        """
        if self.role != Role.PRIMARY:
            logger.warning(f"push_update_to_backups called on a non-primary {self.replica_id}. Ignored.")
            return
        
        for backup_id, stub in self.stub_cache.items():
            try:
                req = message_service_extensions_pb2.UpdateRequest(
                    update_type=update_type,
                    parameters=parameters
                )
                stub.PushUpdate(req, timeout=3)
                logger.info(f"Successfully pushed update {update_type} to {backup_id}")
            except Exception as e:
                logger.error(f"Failed to push update {update_type} to {backup_id}: {e}")
