import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import asyncio
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import json

class NotificationService:
    def __init__(self, webhook_url, max_retries=3, pool_connections=10, pool_maxsize=10):
        self.webhook_url = webhook_url
        self.message_queue = Queue()
        self.session = self._create_session(max_retries, pool_connections, pool_maxsize)
        self.executor = ThreadPoolExecutor(max_workers=5)

    def _create_session(self, max_retries, pool_connections, pool_maxsize):
        session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def send_notification(self, message):
        """Synchronous notification sending"""
        headers = {'Content-type': 'application/json'}
        try:
            response = self.session.post(
                self.webhook_url,
                data=json.dumps(message),
                headers=headers,
                timeout=5
            )
            response.raise_for_status()
            return True, None
        except Exception as e:
            return False, str(e)

    async def send_notification_async(self, message):
        """Asynchronous notification sending"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            self.send_notification,
            message
        )

    def queue_notification(self, message):
        """Add message to queue for batch processing"""
        self.message_queue.put(message)

    def process_queue(self):
        """Process all queued messages"""
        while not self.message_queue.empty():
            message = self.message_queue.get()
            success, error = self.send_notification(message)
            if not success:
                # Requeue failed messages
                self.queue_notification(message)
