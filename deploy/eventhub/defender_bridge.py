#!/usr/bin/env python3
"""Stream Defender Event Hubs envelopes to Tally; checkpoint only acknowledged events.

Credentials are read from environment or DefaultAzureCredential, never CLI arguments or logs.
Run this service in the customer's Azure region. It does not install software on endpoints.
"""
import asyncio
import logging
import os
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from azure.eventhub.aio import EventHubConsumerClient
from azure.eventhub.extensions.checkpointstoreblobaio import BlobCheckpointStore
from azure.identity.aio import DefaultAzureCredential


async def forward(partition, event):
    if event is None:
        return
    delay = 1
    while True:
        try:
            body = event.body_as_str(encoding="UTF-8").encode("utf-8")
            if len(body) > 64 * 1024 * 1024:
                raise ValueError("Defender event exceeds Tally batch size")
            await asyncio.to_thread(post, body)
            await partition.update_checkpoint(event)
            return
        except Exception:
            # Keep the partition paused, including malformed/oversized events and checkpoint
            # failures. The SDK must never continue to a later event after this one failed.
            # Cancellation is a BaseException and propagates normally during shutdown.
            logging.warning("Event not acknowledged and checkpointed; partition paused for retry")
            await asyncio.sleep(delay)
            delay = min(60, delay * 2)


def post(body):
    request = urllib.request.Request(
        os.environ["TALLY_RECEIVER_URL"], data=body,
        headers={"Authorization": os.environ["TALLY_RECEIVER_AUTHORIZATION"],
                 "Content-Type": "application/json"}, method="POST",
    )
    # Never follow redirects with authorization or telemetry.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
        if response.status not in (200, 204):
            raise OSError("Tally ingestion was not acknowledged")


async def main():
    logging.basicConfig(level=logging.WARNING)
    endpoint = urlsplit(os.environ["TALLY_RECEIVER_URL"])
    if endpoint.scheme != "https" and not (endpoint.scheme == "http" and endpoint.hostname in ("127.0.0.1", "localhost", "::1")):
        raise ValueError("Tally receiver requires HTTPS except for loopback")
    async with DefaultAzureCredential() as credential:
        store = BlobCheckpointStore(
            blob_account_url=os.environ["AZURE_CHECKPOINT_BLOB_URL"],
            container_name=os.environ["AZURE_CHECKPOINT_CONTAINER"], credential=credential,
        )
        client = EventHubConsumerClient(
            fully_qualified_namespace=os.environ["AZURE_EVENTHUB_NAMESPACE"],
            eventhub_name=os.environ["AZURE_EVENTHUB_NAME"],
            consumer_group=os.environ.get("AZURE_EVENTHUB_CONSUMER_GROUP", "tally"),
            credential=credential, checkpoint_store=store,
        )
        try:
            async with client:
                # Replay from the earliest available event when no checkpoint exists. Existing
                # partition checkpoints always win. No later event can bypass a failed POST.
                await client.receive(on_event=forward, starting_position="-1")
        finally:
            await store.close()


if __name__ == "__main__":
    asyncio.run(main())
