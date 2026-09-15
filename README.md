# Firewall Blocker - Deployment Guide

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
- **Modern UI**: Beautiful glassmorphism design with real-time updates

## Installation

```bash
git clone https://github.com/lukasmiller-rgb/firewall-blocker.git
cd firewall-blocker
npm install
```

## Local Development

```bash
npm start
```

Access at: `http://localhost:3000`

## Deployment Options

### Option 1: Deploy to Railway (Recommended - Easiest)

1. Go to [railway.app](https://railway.app)
2. Click "New Project"
3. Select "Deploy from GitHub"
4. Connect your GitHub account and select `firewall-blocker`
5. Railway will auto-detect the Node.js app
6. Click Deploy and get your public URL!

### Option 2: Deploy to Render

1. Go to [render.com](https://render.com)
2. Click "New +" and select "Web Service"
3. Connect your GitHub repository
4. Fill in the details:
   - **Name**: firewall-blocker
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
5. Click "Create Web Service"

### Option 3: Deploy to Heroku

1. Install [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli)
2. Run:
   ```bash
   heroku login
   heroku create firewall-blocker
   git push heroku main
   heroku open
   ```

### Option 4: Use ngrok for Quick Public Access

1. Install [ngrok](https://ngrok.com)
2. Start your local server:
   ```bash
   npm start
   ```
3. In another terminal:
   ```bash
   ngrok http 3000
   ```
4. Copy the public URL from ngrok output

## Configuration

Create a `.env` file in the root directory (optional):

```env
PORT=3000
NODE_ENV=production
```

## Usage

### Starting the Application

**Local:**
```bash
npm start
```

**Production:**
The deployed version will be available at your deployment URL.

### API Endpoints

- `GET /` - Main web interface
- `POST /api/check-access` - Check if URL/IP is accessible
- `POST /api/block` - Add to blocked list
- `POST /api/allow` - Add to allowed list
- `POST /api/unblock` - Remove from blocked list
- `GET /api/lists` - View all lists
- `GET /health` - Health check

## How to Use

1. **Check Access** - Enter a URL, domain, or IP to verify accessibility
2. **Block** - Add URLs/domains/IPs to the blocked list
3. **Allow** - Whitelist URLs/domains/IPs to override blocks
4. **View Lists** - See all blocked and allowed items with type badges
5. **Remove** - Delete items from either list anytime

## Architecture

```
src/
├── index.js           # Express server with API endpoints
public/
├── index.html         # Modern UI with glassmorphism design
├── assets/
└── styles/
.gitignore
package.json
README.md
```

## Technology Stack

- **Backend**: Node.js + Express
- **Frontend**: HTML5 + CSS3 + Vanilla JavaScript
- **Styling**: Modern Glassmorphism with Gradient UI
- **Icons**: FontAwesome 6.4.0
- **HTTP Client**: Axios for URL verification

## Environment Variables

- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment (development/production)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT

## Support

For issues or questions, please open an issue on GitHub.

---

**Deployed? Share your public URL!** 🚀
