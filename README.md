# DAPI Auth Toolkit – 2026 Edition

High-performance authentication & session management utilities for Discord API interaction.  
Built for advanced testing of authentication flows, session persistence, proxy-aware requests and rate-limit handling.

**Research & Educational Disclaimer**  
This is a proof-of-concept project created for **educational, security research, red-team exercises and authorized API testing purposes only**.  
Any use for unauthorized account access, credential stuffing, token harvesting, account takeover or violation of any platform's Terms of Service is strictly prohibited. The author assumes no responsibility for misuse.

## Core Features
- curl_cffi-based client with Chrome 126+ impersonation (advanced TLS/JA3/JA4 evasion)
- Ultra-aggressive residential proxy rotation (1 request per proxy lifetime)
- Redis-backed shared state (combo queue, proxy health tracking, rate limiting, refresh tokens)
- 7-layer captcha solving chain (capsolver → 2captcha → anticaptcha → deathbycaptcha → rucaptcha → anycaptcha → skip)
- Automatic refresh token daemon (runs every 30–90 minutes)
- Global behavioral & rate-limit cooldown system (detects patterns across proxies/subnets)
- Deep per-request fingerprint randomization (build number, UA, locale, sec-ch-ua, etc.)
- Subnet / ASN / per-proxy / per-fingerprint rate tracking

## Requirements
- Python 3.10+
- Redis server (local or clustered)
- Large residential / 4G proxy pool (10k–50k+ recommended)

```bash
pip install redis aioredis curl-cffi fake-useragent aiofiles
# Optional captcha solvers – install only those you have API keys for
pip install capsolver twocaptcha anticaptcha deathbycaptcha rucaptcha anycaptcha
Quick Setup

Configure Redis connection, webhook URL and captcha API keys at the top of the script
Prepare residential_proxies.txt (one proxy per line)
Prepare combos.txt (email:password format – research/test data only)
Start Redis server
Run: python dapi_toolkit.py
