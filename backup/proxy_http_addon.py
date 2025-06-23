########## FILTER SECTION ##########

# Session-specific logic tracker
ALL_SESSIONS = {}
SESSIONIZED = False

FLAG_REGEX = rb'[A-Z0-9]{31}='
FLAG_REPLACEMENT = "GRAZIEDARIO"
BLOCK_ALL_EVIL = True
BLOCKING_ERROR= b"Internal Server Error\r\n"
ALL_REGEXES = [
    rb'banana',
]

#ALLOWED_AGENTS = [r''] # allow everyone
ALLOWED_AGENTS = [r"^CHECKER$"]
BANNED_AGENTS = [r"requests"]

########### FILTERS ##########

def regex_filter(flow, session_id):
    if any(check_whole_request(flow, reg) for reg in ALL_REGEXES):
        if session_id:
            ALL_SESSIONS[session_id] = True
        replace_flag(flow)

FILTERS = [
    regex_filter
]

########## UTILITY FUNCTIONS ##########

def replace_flag(flow):

    def callback(match_obj):
        new_flag = FLAG_REPLACEMENT
        return new_flag.encode()

    search = re.search(FLAG_REGEX, flow.response.content)
    if BLOCK_ALL_EVIL:
        flow.response.raw_content = BLOCKING_ERROR
        flow.response.status_code = 500
    elif search:
        flow.response.content = re.sub(FLAG_REGEX, callback, flow.response.content)

def check_user_agent(flow):
    agents = flow.request.headers.get_all("User-Agent")
    print(f"User-Agent: {agents}")
    if not agents:
        logger.info("No user agent found!")
        return
    
    agent = agents[0] 
    for check in ALLOWED_AGENTS:
        match = re.search(check, agent)
        if match:
            logger.debug(f"Allowed user agent! {check} ~ {agent}")
            return
    
    for check in BANNED_AGENTS:
        match = re.search(check, agent)
        if match:
            logger.warning(f"Banned user agent! {check} ~ {agent}")
            replace_flag(flow)
            return

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
            logger.debug(f"Found session id {session_id}")
        else:
            logger.debug("No session id found!")
            session_id = None
    return session_id

########## LOGGER ##########

import logging

class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[94m",    # Blue
        "INFO": "\033[97m",     # White
        "WARNING": "\033[93m",  # Yellow
        "ERROR": "\033[91m",    # Red
        "CRITICAL": "\033[95m", # Magenta
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        message = super().format(record)
        return f"{color}{message}{self.RESET}"

logger = logging.getLogger("mitm_logger")
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
handler.setFormatter(ColorFormatter("[%(levelname)s] %(message)s"))

logger.addHandler(handler)

########## ADDON ##########

from mitmproxy import http
import re

class ProxyAddon:
    def __init__(self):
        logger.info("[🔧] HTTPS ProxyAddon reloaded")

    def response(self, flow: http.HTTPFlow):
        session_id = None
        if SESSIONIZED:
            session_id = find_session_id(flow)
            if session_id:
                logger.info(f"Session ID: {session_id}")
                if ALL_SESSIONS.get(session_id, False):
                    replace_flag(flow)
                    return
        try:
            for f in FILTERS:
                f(flow, session_id)
        except Exception as e:
            logger.error(f"[❌] Filter error: {e}")
            

addons = [ProxyAddon()]
