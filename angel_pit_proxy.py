########## FILTER SECTION ##########

# Session-specific logic tracker
from cachetools import TTLCache

SESSION_TTL = 20  # seconds
SESSION_LIMIT = 1000  # max sessions to keep in memory

ALL_SESSIONS = TTLCache(maxsize=SESSION_LIMIT, ttl=SESSION_TTL)

SESSIONIZED = False

FLAG_REGEX = rb'[A-Z0-9]{31}='
FLAG_REPLACEMENT = "GRAZIEDARIO"
BLOCK_ALL_EVIL = False
BLOCKING_ERROR= b"Internal Server Error\n"
ALL_REGEXES = [
    rb'banana',
]

USERAGENTS_WHITELIST = [
    r"CHECKER"
]
USERAGENTS_BLACKLIST = [
    r"requests"
]

########### FILTERS ##########

def regex_filter(ctx):
    if any(re.search(reg, ctx.raw_request) for reg in ALL_REGEXES):
        if ctx.session_id:
            logger.info(f"[🔍] Regex match found in session {ctx.session_id}")
            ALL_SESSIONS[ctx.session_id] = True
        replace_flag(ctx.flow)

def whitelist_useragent(ctx):
    user_agents = ctx.flow.request.headers.get_all("User-Agent")
    agent = user_agents[0] if user_agents else None

    logger.debug(f"User-Agent: {agent or 'None'}")

    if not agent or not any(re.search(allowed, agent) for allowed in USERAGENTS_WHITELIST):
        logger.debug("Blocked or missing User-Agent.")
        replace_flag(ctx.flow)

def blacklist_useragent(ctx):
    user_agents = ctx.flow.request.headers.get_all("User-Agent")
    agent = user_agents[0] if user_agents else None
    logger.debug(f"User-Agent: {agent or 'None'}")

    if agent and any(re.search(banned, agent) for banned in USERAGENTS_BLACKLIST):
        logger.debug(f"Blocked User-Agent: {agent}")
        replace_flag(ctx.flow)

FILTERS = [
    regex_filter,
    whitelist_useragent
]

########## UTILITY FUNCTIONS ##########

def replace_flag(flow):
    if flow.type == "http" and flow.response:
        flow.response.status_code = 500 if BLOCK_ALL_EVIL else flow.response.status_code
        flow.response.raw_content = BLOCKING_ERROR if BLOCK_ALL_EVIL else re.sub(FLAG_REGEX, FLAG_REPLACEMENT.encode(), flow.response.content)
    elif flow.type == "tcp":
        for msg in reversed(flow.messages):
            if not msg.from_client:
                msg.content = BLOCKING_ERROR if BLOCK_ALL_EVIL else re.sub(FLAG_REGEX, FLAG_REPLACEMENT.encode(), msg.content)
                break

def check_whole_request(flow, regex):
    header_bytes = b'\n'.join(f"{k}: {v}".encode() for k, v in flow.request.headers.items())
    full = flow.request.raw_content or b''
    return re.search(regex, header_bytes + b'\r\n' + full)

def find_session_id(flow):
    # Try to extract session ID from Set-Cookie or Cookie header
    session_id = None
    
    
    for h in flow.response.headers.get_all("Set-Cookie"):
        m = re.search(r'session=([^;]+)', h)
        if m:
            session_id = m.group(1)
            ALL_SESSIONS[session_id] = False
            logger.debug(f"Tracking new session id {session_id}")
            break

    if not session_id:
        cookies = flow.request.cookies.get_all("session")
        if cookies:
            session_id = cookies[0]
            if session_id not in ALL_SESSIONS:
                ALL_SESSIONS[session_id] = False
            logger.debug(f"Found session id {session_id}")
        else:
            logger.debug("No session id found!")
            session_id = None
    return session_id

########## LOGGER ##########

import logging

# Define custom SUCCESS log level (between INFO=20 and WARNING=30)
SUCCESS_LEVEL_NUM = 25
logging.addLevelName(SUCCESS_LEVEL_NUM, "SUCCESS")

def success(self, message, *args, **kwargs):
    if self.isEnabledFor(SUCCESS_LEVEL_NUM):
        self._log(SUCCESS_LEVEL_NUM, message, args, **kwargs)

# Add the method to the logger class
logging.Logger.success = success

# Colored formatter with SUCCESS support
class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[94m",    # Blue
        "INFO": "\033[97m",     # White
        "SUCCESS": "\033[92m",  # Green
        "WARNING": "\033[93m",  # Yellow
        "ERROR": "\033[91m",    # Red
        "CRITICAL": "\033[95m", # Magenta
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        message = super().format(record)
        return f"{color}{message}{self.RESET}"

# Setup logger
logger = logging.getLogger("mitm_logger")
logger.setLevel(logging.INFO) 

handler = logging.StreamHandler()
handler.setFormatter(ColorFormatter("[%(levelname)s] %(message)s"))
logger.addHandler(handler)

########## CONTEXT ##########

class FlowContext:
    def __init__(self, flow):
        self.flow = flow
        self.type = "http" if hasattr(flow, "request") else "tcp"
        self.raw_request = b""
        self.raw_response = b""
        self.session_id = None

        if self.type == "http":
            method = flow.request.method
            path = flow.request.path  # includes query string
            http_version = flow.request.http_version  # usually "HTTP/1.1"

            request_line = f"{method} {path} {http_version}\r\n".encode()

            headers = b"".join(f"{k}: {v}\r\n".encode() for k, v in flow.request.headers.items())
            body = flow.request.raw_content or b""

            self.raw_request = request_line + headers + b"\r\n" + body

            status_code = flow.response.status_code
            reason = flow.response.reason  # e.g., "OK"
            http_version = flow.response.http_version  # usually "HTTP/1.1"

            status_line = f"{http_version} {status_code} {reason}\r\n".encode()

            headers = b"".join(f"{k}: {v}\r\n".encode() for k, v in flow.response.headers.items())
            body = flow.response.raw_content or b""

            self.raw_response = status_line + headers + b"\r\n" + body

            self.session_id = find_session_id(flow)

        elif self.type == "tcp":
            self.raw_request = b"".join(m.content for m in flow.messages if m.from_client)
            self.raw_response = b"".join(m.content for m in flow.messages if not m.from_client)


########## MAIN ##########

from mitmproxy import http, tcp
import re

class ProxyAddon:
    def __init__(self):
        logger.success("[🔧] ProxyAddon reloaded")

    def response(self, flow: http.HTTPFlow):
        ctx = FlowContext(flow)

        if SESSIONIZED and ctx.session_id:
            logger.debug(f"[📦] Session ID: {ctx.session_id}")
            if ALL_SESSIONS.get(ctx.session_id):
                replace_flag(ctx.flow)
                return

        try:
            for f in FILTERS:
                f(ctx)
        except Exception as e:
            logger.error(f"[❌] Filter error: {e}")

    def tcp_message(self, flow: tcp.TCPFlow):
        ctx = FlowContext(flow)
        logger.info(f"[📥] TCP message ({len(flow.messages)} messages)")

        try:
            for f in FILTERS:
                f(ctx)
        except Exception as e:
            logger.error(f"[❌] TCP Filter error: {e}")
            

# This ensures only one instance is registered, even during hot reload
addons = [
    ProxyAddon()
]
