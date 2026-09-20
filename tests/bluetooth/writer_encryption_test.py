import asyncio
import unittest

from bluetti_bt_lib import DeviceWriter, DeviceWriterConfig
from bluetti_bt_lib.devices.el30v2 import EL30V2
from bluetti_bt_lib.fields import FieldName


class RecordingClient:
    def __init__(self):
        self.address = "00:11:00:11:00:11"
        self.is_connected = True
        self.writes = []
        self.notifier = None

    async def connect(self):
        self.is_connected = True

    async def disconnect(self):
        self.is_connected = False

    async def start_notify(self, uuid, handler):
        self.notifier = handler

    async def stop_notify(self, uuid):
        self.notifier = None

    async def write_gatt_char(self, uuid, data):
        self.writes.append(bytes(data))


def make_writer(use_encryption: bool):
    client = RecordingClient()
    writer = DeviceWriter(
        client,
        EL30V2(),
        DeviceWriterConfig(timeout=1, use_encryption=use_encryption),
    )
    return writer, client


class TestEncryptedWrites(unittest.IsolatedAsyncioTestCase):
    async def test_plaintext_write_is_unchanged(self):
        writer, client = make_writer(False)

        await writer.write(FieldName.CTRL_AC.value, True)

        self.assertEqual(len(client.writes), 1)
        self.assertFalse(client.is_connected)

    async def test_encrypted_write_waits_for_the_handshake(self):
        writer, client = make_writer(True)

        await writer.write(FieldName.CTRL_AC.value, True)

        # The handshake never completes, so the command must not be sent in
        # the clear; the outer timeout ends the attempt.
        self.assertEqual(client.writes, [])

    async def test_encrypted_write_abandons_a_failed_handshake(self):
        writer, client = make_writer(True)

        async def fail_soon():
            await asyncio.sleep(0.05)
            writer.session.failed = True

        asyncio.get_running_loop().create_task(fail_soon())
        await writer.write(FieldName.CTRL_AC.value, True)

        self.assertEqual(client.writes, [])
        self.assertFalse(client.is_connected)

    async def test_encrypted_write_sends_ciphertext_once_ready(self):
        writer, client = make_writer(True)
        plaintext = bytes(writer.bluetti_device.build_write_command(
            FieldName.CTRL_AC.value, True
        ))

        async def finish_handshake():
            await asyncio.sleep(0.05)
            writer.session.encryption.secure_aes_key = bytes(range(16))
            writer.session.encryption.peer_pubkey = object()

        asyncio.get_running_loop().create_task(finish_handshake())
        await writer.write(FieldName.CTRL_AC.value, True)

        self.assertEqual(len(client.writes), 1)
        self.assertNotEqual(client.writes[0], plaintext)
        self.assertGreater(len(client.writes[0]), len(plaintext))
