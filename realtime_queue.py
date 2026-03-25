from queue import Queue

# Shared queue for communication between IDS and Flask app
realtime_queue = Queue(maxsize=1000)