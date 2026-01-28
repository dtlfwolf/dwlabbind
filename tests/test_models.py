import unittest

from dwlabbind.models import BindServer, BindZone, HAConfig, SecurityConfig, TSIGKey


class TestModels(unittest.TestCase):
    def test_bind_server_roundtrip_dict(self) -> None:
        key = TSIGKey(name="transfer-key", algorithm="hmac-sha256", secret="secret")
        security = SecurityConfig(
            enabled=True,
            allow_recursion=["10.0.0.0/8"],
            allow_transfer=["192.0.2.0/24"],
            tsig_keys=[key],
        )
        ha = HAConfig(enabled=True, mode="active-active", peers=["10.0.0.2"])
        zone = BindZone(name="example.com", zone_type="master", file="db.example.com")
        server = BindServer(
            name="ns1",
            ip="192.0.2.10",
            port=5353,
            role="master",
            zones=[zone],
            security=security,
            high_availability=ha,
        )

        payload = server.to_dict()
        rebuilt = BindServer.from_dict(payload)

        self.assertEqual(rebuilt.name, server.name)
        self.assertEqual(rebuilt.ip, server.ip)
        self.assertEqual(rebuilt.port, server.port)
        self.assertEqual(rebuilt.role, server.role)
        self.assertEqual(len(rebuilt.zones), 1)
        self.assertEqual(rebuilt.zones[0].name, "example.com")
        self.assertTrue(rebuilt.security.enabled)
        self.assertEqual(rebuilt.security.allow_recursion, ["10.0.0.0/8"])
        self.assertEqual(rebuilt.security.allow_transfer, ["192.0.2.0/24"])
        self.assertEqual(rebuilt.security.tsig_keys[0].name, "transfer-key")
        self.assertTrue(rebuilt.high_availability.enabled)
        self.assertEqual(rebuilt.high_availability.mode, "active-active")
        self.assertEqual(rebuilt.high_availability.peers, ["10.0.0.2"])

    def test_zone_add_remove(self) -> None:
        server = BindServer(name="ns1", ip="192.0.2.10")
        zone = BindZone(name="example.com", zone_type="master", file="db.example.com")
        server.add_zone(zone)
        self.assertEqual(len(server.zones), 1)
        server.remove_zone("example.com")
        self.assertEqual(len(server.zones), 0)


if __name__ == "__main__":
    unittest.main()
