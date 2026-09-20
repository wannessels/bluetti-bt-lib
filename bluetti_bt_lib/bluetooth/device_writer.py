import asyncio
import logging
from typing import Any
import async_timeout
from bleak import BleakClient
from bleak.exc import BleakError

from .encrypted_session import EncryptedSession
from ..const import NOTIFY_UUID, WRITE_UUID
from ..base_devices import BluettiDevice
from ..utils.privacy import mac_loggable


class DeviceWriterConfig:
    def __init__(self, timeout: int = 15, use_encryption: bool = False):
        self.timeout = timeout
        self.use_encryption = use_encryption


class DeviceWriter:
    def __init__(
        self,
        bleak_client: BleakClient,
        bluetti_device: BluettiDevice,
        config: DeviceWriterConfig = DeviceWriterConfig(),
        lock: asyncio.Lock = asyncio.Lock(),
    ):
        self.client = bleak_client
        self.bluetti_device = bluetti_device
        self.config = config
        self.polling_lock = lock

        self.logger = logging.getLogger(
            f"{__name__}.{mac_loggable(bleak_client.address).replace(':', '_')}"
        )

        self.session = EncryptedSession(self.logger)
        self.has_notifier = False

    async def write(self, field: str, value: Any):
        available_fields = [f.name for f in self.bluetti_device.fields]
        if field not in available_fields:
            self.logger.error("Field not supported")
            return

        command = self.bluetti_device.build_write_command(field, value)

        if command is None:
            self.logger.error("Field is not writeable")
            return

        self.logger.debug("Writing to device register")
        self.session.start()

        async with self.polling_lock:
            try:
                async with async_timeout.timeout(self.config.timeout):
                    if not self.client.is_connected:
                        self.logger.debug("Connecting to device")
                        await self.client.connect()

                    self.logger.debug("Connected to device")

                    command_bytes = bytes(command)

                    if self.config.use_encryption is True:
                        if not await self._handshake():
                            return None
                        command_bytes = self.session.encrypt_command(command_bytes)

                    self.logger.debug("Writing command: %s", command)

                    await self.client.write_gatt_char(WRITE_UUID, command_bytes)

                    self.logger.debug("Write successful")

            except TimeoutError:
                self.logger.warning("Timeout")
                return None
            except BleakError as err:
                self.logger.warning("Bleak error: %s", err)
                return None
            except BaseException as err:
                self.logger.warning("Unknown error: %s", err)
                return None
            finally:
                if self.has_notifier:
                    try:
                        await self.client.stop_notify(NOTIFY_UUID)
                    except BleakError:
                        pass
                    self.has_notifier = False
                self.session.reset()
                await self.client.disconnect()
                self.logger.debug("Disconnected from device")

    async def _handshake(self) -> bool:
        """Wait for the key exchange the unit demands before it accepts a command."""
        if not self.has_notifier:
            await self.client.start_notify(NOTIFY_UUID, self._notification_handler)
            self.has_notifier = True

        while not self.session.is_ready:
            if self.session.failed:
                self.logger.warning("Handshake failed, not writing")
                return False
            await asyncio.sleep(0.2)

        return True

    async def _notification_handler(self, _: int, data: bytearray):
        await self.session.consume(data, self.client)
