# Networking, IPv6, and Firewall Configuration

This document covers networking, IPv6 considerations, firewall requirements, and rule persistence on Debian Linux.

---

## 1. Dual-Stack IPv4 / IPv6 Considerations

### Let's Encrypt IPv6 Preference
If a domain name has both an **A** (IPv4) record and an **AAAA** (IPv6) record, the Let's Encrypt CA validation servers **always prioritize IPv6** when verifying HTTP-01 challenges.

- If IPv4 port 80 is open to the internet, but incoming IPv6 port 80 is blocked by a local firewall, certificate issuance **will fail with a connection timeout**.
- Both IPv4 and IPv6 traffic must be permitted on port 80 for ACME challenges and port 443 for regular HTTPS traffic.

### Go Dual-Stack Listener Binding
When the proxy calls:
```go
net.Listen("tcp", ":80")
net.Listen("tcp", ":443")
```
On modern Linux kernels, binding to `:80` without specifying an IP address binds to the dual-stack wildcard socket `[::]:80`, accepting incoming connections from both IPv4 (`0.0.0.0`) and IPv6 (`::`).

---

## 2. Firewall Requirements (`iptables` / `ip6tables`)

For Let's Encrypt to validate certificates and for clients to reach the service, the host machine must allow incoming TCP traffic on ports 80 and 443 from external network interfaces.

### Allowing Inbound Ports

Assuming `enp1s0` is the external WAN interface:

```bash
# Allow IPv6 HTTP (ACME verification) and HTTPS
sudo ip6tables -I INPUT -i enp1s0 -p tcp --dport 80 -j ACCEPT
sudo ip6tables -I INPUT -i enp1s0 -p tcp --dport 443 -j ACCEPT

# Allow IPv4 HTTP and HTTPS (if input policy drops by default)
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
```

---

## 3. Persistent Firewall Rules on Debian

By default, rules added via `iptables` or `ip6tables` are stored in kernel memory and reset upon system reboot. On Debian, rules are persisted using **`netfilter-persistent`** (and `iptables-persistent`).

### Method A: `netfilter-persistent save` (Recommended)

After modifying your active rules, run:

```bash
sudo netfilter-persistent save
```

This dumps the live in-kernel netfilter rules into:
- `/etc/iptables/rules.v4` (IPv4)
- `/etc/iptables/rules.v6` (IPv6)

### Method B: Direct Save with `ip6tables-save`

If you only want to update the IPv6 rules without modifying the IPv4 file:

```bash
sudo ip6tables-save | sudo tee /etc/iptables/rules.v6
```

### Verifying and Testing Reload

1. Inspect the persisted IPv6 rules file:
   ```bash
   cat /etc/iptables/rules.v6
   ```

2. Test reloading rules as the system will do during boot:
   ```bash
   sudo netfilter-persistent reload
   ```

3. Confirm `netfilter-persistent` is enabled to start at boot:
   ```bash
   sudo systemctl is-enabled netfilter-persistent
   ```

---

## 4. Troubleshooting Checklist

| Symptom | Cause | Solution |
|---|---|---|
| `acme/autocert: missing server name` | A client connected to HTTPS via raw IP address without TLS SNI extension. | The proxy automatically falls back to `defaultHostname` and redirects HTTP requests to the canonical domain. |
| `acme/autocert: host not configured` | A request arrived with an SNI domain name not matching the `--hostname` whitelist. | Verify that `--hostname` matches the domain in the DNS record. |
| Let's Encrypt validation times out | Port 80 is blocked on IPv6 (`enp1s0`) by the firewall, or router lacks port-forwarding. | Open port 80 in `ip6tables` and confirm DNS AAAA points to the active IPv6 interface. |
| `permission denied` binding to port 80/443 | Ports below 1024 require elevated privileges in Linux. | Run with `sudo` or grant binary capability: `sudo setcap 'cap_net_bind_service=+ep' ./https-proxy`. |
