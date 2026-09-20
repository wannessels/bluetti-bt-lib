import asyncio
import unittest

from bleak.exc import BleakError

from bluetti_bt_lib.base_devices import BaseDeviceV1
from bluetti_bt_lib import DeviceReader
from bluetti_bt_lib.bluetooth.device_reader import DeviceReaderConfig
from bluetti_bt_lib.bluetooth.encryption import KEX_MAGIC, MessageType, hexsum
from bluetti_bt_lib.fields import FieldName
from bluetti_bt_lib.utils.bleak_client_mock import ClientMockNoEncryption


def build_challenge_frame() -> bytearray:
    """Build a well-formed pre-key-exchange CHALLENGE frame."""
    body = bytes([MessageType.CHALLENGE.value, 0]) + b"\x01\x02\x03\x04"
    return bytearray(KEX_MAGIC + body + hexsum(body, 2))


class FailingWriteClient:
    """BLE client whose writes always fail, as when the peer drops the link."""

    async def write_gatt_char(self, *_args, **_kwargs):
        raise BleakError("Not connected")


class TestDeviceReader(unittest.IsolatedAsyncioTestCase):
    def __init__(self, methodName="runTest"):
        super().__init__(methodName)
        self.ble_mock = ClientMockNoEncryption()

        # Device type
        self.ble_mock.add_r_str(10, "AC300", 6)
        # Serial
        self.ble_mock.add_r_sn(17, 2300000000000)
        # DC input power
        self.ble_mock.add_r_int(36, 10)
        # AC input power
        self.ble_mock.add_r_int(37, 8)
        # AC output power
        self.ble_mock.add_r_int(38, 9)
        # AC output power
        self.ble_mock.add_r_int(39, 7)
        # SOC
        self.ble_mock.add_r_int(43, 78)

    async def test_read_all_correct(self):
        device = BaseDeviceV1()
        reader = DeviceReader(
            "00:11:00:11:00:11",
            device,
            asyncio.Future,
            ble_client=self.ble_mock,
        )

        data = await reader.read()

        self.assertEqual(data.get(FieldName.DEVICE_TYPE.value), "AC300")
        self.assertEqual(data.get(FieldName.DEVICE_SN.value), 2300000000000)
        self.assertEqual(data.get(FieldName.DC_INPUT_POWER.value), 10)
        self.assertEqual(data.get(FieldName.AC_INPUT_POWER.value), 8)
        self.assertEqual(data.get(FieldName.AC_OUTPUT_POWER.value), 9)
        self.assertEqual(data.get(FieldName.DC_OUTPUT_POWER.value), 7)
        self.assertEqual(data.get(FieldName.BATTERY_SOC.value), 78)

    async def test_notification_with_done_future(self):
        # Late or duplicate notifications must not raise InvalidStateError (#64)
        device = BaseDeviceV1()
        reader = DeviceReader(
            "00:11:00:11:00:11",
            device,
            asyncio.Future,
            ble_client=self.ble_mock,
        )

        # First notification resolves the future
        reader.notify_future = asyncio.Future()
        await reader._notification_handler(0, bytearray(b"\x01\x02"))
        self.assertTrue(reader.notify_future.done())

        # Duplicate notification arriving after the future is resolved
        await reader._notification_handler(0, bytearray(b"\x03\x04"))
        self.assertEqual(reader.notify_future.result(), bytearray(b"\x01\x02"))

        # Late notification after the future was cancelled (response timeout)
        reader.notify_response = bytearray()
        reader.notify_future = asyncio.Future()
        reader.notify_future.cancel()
        await reader._notification_handler(0, bytearray(b"\x05\x06"))
        self.assertTrue(reader.notify_future.cancelled())

    async def test_read_soc_wrong(self):
        # SOC
        self.ble_mock.add_r_int(43, 1234)

        device = BaseDeviceV1()
        reader = DeviceReader(
            "00:11:00:11:00:11",
            device,
            asyncio.Future,
            ble_client=self.ble_mock,
        )

        data = await reader.read()

        self.assertIsNone(data.get(FieldName.BATTERY_SOC.value))

    async def test_handshake_write_failure_is_contained(self):
        # A write can fail mid-handshake when the peripheral drops the link.
        # The notification handler must not let BleakError escape into bleak's
        # callback dispatch, where it surfaces without naming the stalled read.
        reader = DeviceReader(
            "00:11:00:11:00:11",
            BaseDeviceV1(),
            asyncio.Future,
            config=DeviceReaderConfig(use_encryption=True),
        )
        reader.client = FailingWriteClient()

        await reader._notification_handler(0, build_challenge_frame())
