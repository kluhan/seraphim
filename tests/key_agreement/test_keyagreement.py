import pytest
import secrets

from seraphim.key_agreement.key_agreement import KeyAgreement

class TestKeyAgreement:

    @pytest.fixture
    def domains(self):
        return ["curve25519", "secp256k1", "p-384"]
    
    @pytest.fixture
    def styles(self):
        return ["projective", "affine"]

    def test_key_agreement(self, styles, domains):
        for style in styles:
            for domain in domains:
                key_agreement_alice = KeyAgreement(domain, style, v=False)
                key_agreement_bob = KeyAgreement(domain, style, v=False)

                local_key_alice = key_agreement_alice.compute_local_key()
                local_key_bob = key_agreement_bob.compute_local_key()

                key_alice = key_agreement_alice.compute_shared_key(local_key_bob)
                key_bob = key_agreement_bob.compute_shared_key(local_key_alice)

                assert key_alice == key_bob

                message_alice = secrets.token_urlsafe(4096)
                message_bob = secrets.token_urlsafe(4096)

                for_bob_encrypted = key_agreement_alice.encrypt(message_alice)            
                for_alice_encrypted = key_agreement_bob.encrypt(message_bob)

                for_bob_decypted = key_agreement_bob.decrypt(for_bob_encrypted)
                for_alice_decrypted = key_agreement_alice.decrypt(for_alice_encrypted)

                assert message_alice == for_bob_decypted
                assert message_bob == for_alice_decrypted
