# Virtual Hosts Configuration

Virtual hosts allow you to run a single HTTPS proxy server that can route requests to different backend services based on the incoming hostname.

## Configuration

Virtual hosts are configured using a JSON file that maps hostnames to backend URLs.

### Configuration File Format

Create a JSON file with the following structure:

```json
{
  "virtual_hosts": [
    {
      "hostname": "api.example.com",
      "backend": "http://localhost:8080"
    },
    {
      "hostname": "web.example.com",
      "backend": "http://localhost:3000"
    },
    {
      "hostname": "admin.example.com",
      "backend": "http://localhost:9000"
    }
  ]
}
```

### Field Descriptions

- **hostname**: The HTTPS hostname that clients will connect to. This must be a valid domain name.
- **backend**: The HTTP or HTTPS URL of the backend service to proxy requests to. Must start with `http://` or `https://`.

## Usage

### Run with Virtual Hosts Configuration

```bash
sudo ./https-proxy --virtual-hosts virtual-hosts.json --oauth --verbose
```

### Flags

- `--virtual-hosts <path>`: Path to the JSON configuration file containing virtual host mappings
  - When this flag is provided, `--hostname` and `--backend` flags are ignored
  - Let's Encrypt will automatically manage certificates for all configured hostnames
  
### Backward Compatibility

The proxy maintains full backward compatibility with the existing single-host configuration:

```bash
# Traditional single-host mode (still works)
sudo ./https-proxy --hostname example.com --backend http://localhost:8080 --oauth
```

If `--virtual-hosts` is not specified, the proxy requires both `--hostname` and `--backend` flags.

## Certificate Management

When using virtual hosts, Let's Encrypt will automatically provision and renew TLS certificates for all configured hostnames:

```
HTTPS listening on :443 with 4 virtual host(s)
Using Let's Encrypt certificates for 4 host(s)
  - api.example.com -> http://localhost:8080
  - web.example.com -> http://localhost:3000
  - admin.example.com -> http://localhost:9000
  - app.example.com -> https://internal-backend:8443
```

### Certificate Caching

Certificates are cached in the default location (`$HOME/.cache/https-proxy`) and can be customized with `--cache-dir`.

### Using Self-Signed Certificates

When using `--self-signed` with virtual hosts, a single certificate for the primary hostname is required:

```bash
./https-proxy --virtual-hosts virtual-hosts.json --self-signed
```

The self-signed certificate should be generated for the first hostname in the configuration file.

## Hostname Matching

- Hostname matching is **case-insensitive**
- If a request arrives for an unknown hostname not in the configuration, it will be routed to the default backend (the first one specified)
- Hostnames can include ports (e.g., `example.com:8443`), but matching is performed on the hostname part only

## OAuth with Virtual Hosts

OAuth authentication is enforced on all virtual hosts. The OAuth redirect URL will be set to the first configured hostname:

```
OAuth authentication ENFORCED (callback: /callback)
```

All configured hostnames can use the same OAuth credentials.

## Example: Multi-Service Architecture

```json
{
  "virtual_hosts": [
    {
      "hostname": "api.company.com",
      "backend": "http://api-server:8000"
    },
    {
      "hostname": "web.company.com",
      "backend": "http://web-server:3000"
    },
    {
      "hostname": "admin.company.com",
      "backend": "http://admin-panel:9000"
    },
    {
      "hostname": "grafana.company.com",
      "backend": "http://grafana:3000"
    },
    {
      "hostname": "confluence.company.com",
      "backend": "http://confluence-server:8080"
    }
  ]
}
```

Then run:

```bash
sudo ./https-proxy \
  --virtual-hosts virtual-hosts.json \
  --oauth \
  --oauth-secret secret.json \
  --oauth-allowed-domains company.com \
  --verbose
```

This creates a single HTTPS endpoint with Let's Encrypt certificates that routes requests to different internal services based on hostname.

## Troubleshooting

### "No virtual host configured for hostname"

If a request arrives for a hostname not in the configuration file, a warning is logged and the request is routed to the default backend. Ensure all expected hostnames are included in the virtual hosts configuration.

### Certificate errors

Ensure that:
1. All hostnames in the configuration have valid DNS records pointing to the proxy server
2. The proxy server is accessible on port 80 and 443 from the internet (for Let's Encrypt validation)
3. The cache directory has write permissions

### Mixed HTTP/HTTPS backends

Virtual hosts support both HTTP and HTTPS backends. For example:

```json
{
  "virtual_hosts": [
    { "hostname": "internal.example.com", "backend": "https://secure-backend:8443" },
    { "hostname": "public.example.com", "backend": "http://public-backend:8080" }
  ]
}
```
