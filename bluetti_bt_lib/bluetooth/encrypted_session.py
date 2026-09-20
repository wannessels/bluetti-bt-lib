import logging

from bleak import BleakClient
from bleak.exc import BleakError
from cryptography.exceptions import InvalidSignature

from .encryption import BluettiEncryption, Message, MessageType, AES_BLOCK_SIZE
from ..const import WRITE_UUID


class EncryptedSession:
    """The Bluetti key exchange, shared by the reader and the writer.

    Both sides need an established session before they can talk to a V2 unit,
    and the handshake has enough edge cases that a second copy of it would
    drift from this one.
    """

    def __init__(self, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger(__name__)
        self.encryption = BluettiEncryption()
        self.buffer = bytearray()
        self.failed = False

    @property
    def is_ready(self) -> bool:
        return self.encryption.is_ready_for_commands

    def reset(self):
        self.encryption.reset()
        self.buffer.clear()

    def start(self):
        self.reset()
        self.failed = False

    def encrypt_command(self, command: bytes) -> bytes:
        return self.encryption.aes_encrypt(
            command, self.encryption.secure_aes_key, None
        )

    def _expected_length(self) -> int | None:
        if len(self.buffer) < 2:
            return None

        data_len = (self.buffer[0] << 8) + self.buffer[1]
        _, iv = self.encryption.getKeyIv()
        header_size = 6 if iv is None else 2
        padded_len = (
            (data_len + AES_BLOCK_SIZE - 1) // AES_BLOCK_SIZE
        ) * AES_BLOCK_SIZE

        return header_size + padded_len

    async def consume(self, data: bytearray, client: BleakClient) -> bytes | None:
        """Feed one notification in.

        Returns the application payload, or None when the frame belonged to the
        key exchange and there is nothing for the caller to handle.
        """
        message = Message(data)

        if message.is_pre_key_exchange:
            message.verify_checksum()

            if message.type == MessageType.CHALLENGE:
                challenge_response = self.encryption.msg_challenge(message)
                await self._write(client, challenge_response, "challenge response")
                return None

            if message.type == MessageType.CHALLENGE_ACCEPTED:
                self.logger.debug("Challenge accepted")
                return None

            return None

        if self.encryption.unsecure_aes_key is None:
            self.logger.error("Received encrypted message before key initialization")
            return None

        self.buffer.extend(data)

        expected_len = self._expected_length()
        if expected_len is None or len(self.buffer) < expected_len:
            return None

        complete_message = bytes(self.buffer[:expected_len])
        if len(self.buffer) > expected_len:
            self.buffer = self.buffer[expected_len:]
        else:
            self.buffer.clear()

        key, iv = self.encryption.getKeyIv()

        try:
            decrypted = Message(self.encryption.aes_decrypt(complete_message, key, iv))
        except ValueError as e:
            self.logger.error("Decryption failed: %s", e)
            self.buffer.clear()
            return None

        if decrypted.is_pre_key_exchange:
            decrypted.verify_checksum()
            await self._consume_key_exchange(decrypted, client, key)
            return None

        return decrypted.buffer

    async def _consume_key_exchange(self, decrypted: Message, client, key: bytes):
        try:
            message_type = decrypted.type
        except ValueError:
            self.logger.warning("Unknown key exchange message type")
            return

        if message_type == MessageType.CHALLENGE:
            # Refreshes the IV the peer pubkey is later verified against.
            challenge_response = self.encryption.msg_challenge(decrypted)
            if challenge_response is not None:
                await self._write(
                    client,
                    self.encryption.aes_encrypt(challenge_response, key, None),
                    "challenge response",
                )
            return

        if message_type == MessageType.CHALLENGE_ACCEPTED:
            self.logger.debug("Challenge accepted (encrypted)")
            return

        if message_type == MessageType.PEER_PUBKEY:
            try:
                peer_pubkey_response = self.encryption.msg_peer_pubkey(decrypted)
            except InvalidSignature:
                self.logger.warning(
                    "Peer pubkey signature rejected, restarting handshake"
                )
                self.reset()
                self.failed = True
                return
            await self._write(client, peer_pubkey_response, "peer pubkey")
            return

        if message_type == MessageType.PUBKEY_ACCEPTED:
            self.encryption.msg_key_accepted(decrypted)
            return

    async def _write(self, client, payload, what: str):
        if payload is None:
            return
        try:
            await client.write_gatt_char(WRITE_UUID, payload)
        except BleakError as err:
            # Nothing else will retry this, so the caller must reconnect.
            self.logger.warning("%s write failed: %s", what, err)
            self.failed = True
