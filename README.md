# Firewall Blocker

A robust firewall application for filtering and blocking network traffic based on configurable rules.

## Features

- **IP-based blocking**: Block or allow traffic from specific IP addresses or ranges
- **Port filtering**: Control traffic on specific ports
- **Protocol filtering**: Filter by TCP, UDP, and other protocols
- **Domain blocking**: Block access to specific domains
- **Rule management**: Create, update, and delete firewall rules
- **Logging**: Comprehensive logging of blocked and allowed traffic
- **Performance**: Efficient packet processing with minimal overhead
- **Configuration**: JSON-based rule configuration for easy setup

## Installation

```bash
git clone https://github.com/lukasmiller-rgb/firewall-blocker.git
cd firewall-blocker
npm install
```

## Quick Start

```bash
npm start
```

## Configuration

Create a `firewall.config.json` file in the root directory:

```json
{
  "rules": [
    {
      "id": "rule-1",
      "name": "Block malicious IPs",
      "type": "ip",
      "action": "block",
      "ips": ["192.168.1.100", "10.0.0.50"]
    },
    {
      "id": "rule-2",
      "name": "Block port 23",
      "type": "port",
      "action": "block",
      "ports": [23]
    }
  ],
  "logging": {
    "enabled": true,
    "level": "info",
    "file": "firewall.log"
  }
}
```

## Usage

### Starting the Firewall

```bash
npm start
```

### API Endpoints

- `GET /api/rules` - List all firewall rules
- `POST /api/rules` - Create a new rule
- `PUT /api/rules/:id` - Update a rule
- `DELETE /api/rules/:id` - Delete a rule
- `GET /api/logs` - View firewall logs
- `GET /api/status` - Get firewall status

## Architecture

```
src/
├── core/           # Core firewall logic
├── rules/          # Rule management
├── filters/        # Packet filters
├── logger/         # Logging system
├── api/            # REST API
└── config/         # Configuration
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT
