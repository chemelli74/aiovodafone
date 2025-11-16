"""Implementation of Technicolor's custom modification of SRP."""

import hashlib
import os
from typing import Final

# SRP-6 constants
_GEN: Final = 2
_K: Final = int(
    "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050"
    "a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50"
    "e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b8"
    "55f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773b"
    "ca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748"
    "544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6"
    "af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb6"
    "94b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73",
    16,
)
_C: Final = int("05b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300", 16)
_U: Final = "4a76a9a2402bdd18123389b72ebbda50a30f65aedb90d7273130edea4b29cc4c"

# The byte-length of the modulus K
_K_LEN_BYTES: Final = 256


def _sha256_hex(data: bytes) -> str:
    """Calculate SHA256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


def _sha256_bytes(data: bytes) -> bytes:
    """Calculate SHA256 hash and return as bytes."""
    return hashlib.sha256(data).digest()


class TechnicolorSRP:
    """Technicolor SRP authentication client."""

    def __init__(self, username: str, password: str) -> None:
        """Initialise the SRP client.

        Args:
            username: The username for authentication.
            password: The password for authentication.

        """
        self.username = username
        self.password = password
        self._f_private, self._d_public = self._generate_client_ephemeral()

        # These will be calculated during the flow
        self._client_proof: str | None = None
        self._server_verification: str | None = None
        self._session_key_hash: str | None = None

    @staticmethod
    def _generate_client_ephemeral() -> tuple[int, int]:
        """Generate client's private (F) and public (D) values."""
        rand_bytes = os.urandom(32)
        f_private = int.from_bytes(rand_bytes, byteorder="big")

        # Calculate D = GEN^F mod K
        d_public = pow(_GEN, f_private, _K)

        return f_private, d_public

    @property
    def client_public_key_hex(self) -> str:
        """Return the client public key (D) as a hex string."""
        d_hex = f"{self._d_public:x}"
        if len(d_hex) % 2 == 1:
            return "0" + d_hex
        return d_hex

    def calculate_proofs(self, salt: str, server_public: str) -> str:
        """Calculate session key and authentication proofs.

        Args:
            salt: Salt received from server (hex string).
            server_public: Server's public value B (hex string).

        Returns:
            The client_proof (M) to be sent to the server.

        Raises:
            RuntimeError: If called more than once.
            ValueError: If server provides an invalid public key (B % K == 0)
                        or h == 0.

        """
        if self._client_proof is not None:
            msg = "Proofs have already been calculated."
            raise RuntimeError(msg)

        # Parse server public key B and perform safety check
        b_int = int(server_public, 16)
        if b_int % _K == 0:
            msg = "Invalid server public key (B % K == 0)."
            raise ValueError(msg)

        # Calculate h = SHA256(pad(D) || pad(B))
        d_bytes = self._d_public.to_bytes(_K_LEN_BYTES, byteorder="big")
        b_bytes = b_int.to_bytes(_K_LEN_BYTES, byteorder="big")

        h_bytes = _sha256_bytes(d_bytes + b_bytes)
        h_int = int.from_bytes(h_bytes, byteorder="big")

        # Perform second safety check
        if h_int == 0:
            msg = "Invalid scrambling parameter (h == 0)."
            raise ValueError(msg)

        # Calculate n = SHA256(salt + SHA256(username + ":" + password))
        password_hash = _sha256_bytes(f"{self.username}:{self.password}".encode())
        n_input = bytes.fromhex(salt + password_hash.hex())
        n_bytes = _sha256_bytes(n_input)
        n_int = int.from_bytes(n_bytes, byteorder="big")

        # Calculate a = (C * GEN^n) mod K
        a_int = (_C * pow(_GEN, n_int, _K)) % _K

        # Calculate b = (h * n + F) mod K
        b_value = (h_int * n_int + self._f_private) % _K

        # Calculate session key: g = (B - a)^b mod K
        g_int = pow((b_int - a_int) % _K, b_value, _K)

        # Convert g to hex string (with even length)
        g_hex = f"{g_int:x}"
        if len(g_hex) % 2 == 1:
            g_hex = "0" + g_hex

        # Calculate session key hash B_hash = SHA256(g)
        g_bytes = bytes.fromhex(g_hex)
        self._session_key_hash = _sha256_hex(g_bytes)

        # --- Calculate client proof (M) ---
        d_hex = self.client_public_key_hex
        username_hash = _sha256_hex(self.username.encode())

        y_input = bytes.fromhex(
            _U + username_hash + salt + d_hex + server_public + self._session_key_hash
        )
        self._client_proof = _sha256_hex(y_input)

        # --- Calculate server verification (v) ---
        v_input = bytes.fromhex(d_hex + self._client_proof + self._session_key_hash)
        self._server_verification = _sha256_hex(v_input)

        return self._client_proof

    def verify_server(self, server_proof: str) -> bool:
        """Verify the server's proof (M2).

        Args:
            server_proof: The proof string (M) sent by the server.

        Returns:
            True if the server's proof is valid, False otherwise.

        Raises:
            RuntimeError: If calculate_proofs has not been called first.

        """
        if self._server_verification is None:
            msg = (
                "Server verification value not calculated. Call calculate_proofs first."
            )
            raise RuntimeError(msg)

        return self._server_verification.upper() == server_proof.upper()

    @property
    def session_key_hash(self) -> str:
        """Get the calculated session key hash (B_hash).

        Raises:
            RuntimeError: If calculate_proofs has not been called first.

        """
        if self._session_key_hash is None:
            msg = "Session key hash not calculated. Call calculate_proofs first."
            raise RuntimeError(msg)
        return self._session_key_hash
