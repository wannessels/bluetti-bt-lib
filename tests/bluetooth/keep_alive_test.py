import asyncio
import unittest

from bluetti_bt_lib import DeviceReader, DeviceReaderConfig
from bluetti_bt_lib.base_devices import BaseDeviceV1
from bleak.exc import BleakError

from bluetti_bt_lib.utils.bleak_client_mock import ClientMockNoEncryption


class CountingClient(ClientMockNoEncryption):
    def __init__(self):
        super().__init__()
        self.is_connected = True
        self.notify_starts = 0
        self.disconnects = 0
        self.fail_writes = False

    async def start_notify(self, char_specifier, callback, **kwargs):
        self.notify_starts += 1
        await super().start_notify(char_specifier, callback, **kwargs)

    async def disconnect(self):
        self.disconnects += 1
        self.is_connected = False

    async def write_gatt_char(self, char_specifier, data, **kwargs):
        if self.fail_writes:
            raise BleakError("simulated link loss")
        return await super().write_gatt_char(char_specifier, data, **kwargs)


def make_reader(keep_alive: float):
    client = CountingClient()
    client.add_r_str(10, "AC300", 6)
    client.add_r_sn(17, 2300000000000)
    client.add_r_int(36, 10)
    client.add_r_int(37, 8)
    client.add_r_int(38, 9)
    client.add_r_int(39, 7)
    client.add_r_int(43, 78)
    reader = DeviceReader(
        "00:11:00:11:00:11",
        BaseDeviceV1(),
        asyncio.Future,
        DeviceReaderConfig(keep_alive_seconds=keep_alive),
        ble_client=client,
    )
    return reader, client


class TestKeepAlive(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_by_default_disconnects_every_read(self):
        reader, client = make_reader(0)

        self.assertIsNotNone(await reader.read())
        client.is_connected = True
        self.assertIsNotNone(await reader.read())

        self.assertEqual(client.notify_starts, 2)
        self.assertEqual(client.disconnects, 2)
        self.assertIsNone(reader.client)

    async def test_keep_alive_reuses_the_open_connection(self):
        reader, client = make_reader(30)

        self.assertIsNotNone(await reader.read())
        self.assertIsNotNone(await reader.read())

        self.assertEqual(client.notify_starts, 1)
        self.assertEqual(client.disconnects, 0)
        self.assertIsNotNone(reader.client)

    async def test_idle_connection_is_released(self):
        reader, client = make_reader(0.05)

        self.assertIsNotNone(await reader.read())
        self.assertIsNotNone(reader.client)

        await asyncio.sleep(0.2)

        self.assertEqual(client.disconnects, 1)
        self.assertIsNone(reader.client)

    async def test_a_read_beats_a_pending_release(self):
        reader, client = make_reader(0.1)

        self.assertIsNotNone(await reader.read())
        await asyncio.sleep(0.05)
        self.assertIsNotNone(await reader.read())
        await asyncio.sleep(0.1)

        # The first release must not tear down the link the second read owns.
        self.assertEqual(client.disconnects, 0)
        self.assertIsNotNone(reader.client)

    async def test_a_failed_read_does_not_keep_the_connection(self):
        reader, client = make_reader(30)
        client.fail_writes = True

        self.assertIsNone(await reader.read())

        self.assertIsNone(reader.client)
        self.assertEqual(client.disconnects, 1)
