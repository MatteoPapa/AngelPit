import string
import re
import logging
from http.cookies import SimpleCookie
from cachetools import TTLCache
import mitmproxy

logger = logging.getLogger("mitm_logger")

# HTTP session tracking
TRACK_HTTP_SESSION = True
SESSION_COOKIE_NAME = "session"
SESSION_TTL = 30  # seconds
SESSION_LIMIT = 4000
ALL_SESSIONS = TTLCache(maxsize=SESSION_LIMIT, ttl=SESSION_TTL)

FLAG_REGEX = re.compile(rb"[A-Z0-9]{31}=")
FLAG_REPLACEMENT = "GRAZIEDARIO"
BLOCK_ALL_EVIL = False
BLOCKING_ERROR = """<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>"""
ERROR_RESPONSE = mitmproxy.http.Response.make(500, BLOCKING_ERROR, {"Content-Type": "text/html"})
INFINITE_LOADING_RESPONSE = mitmproxy.http.Response.make(302, "", {"Location": "https://stream.wikimedia.org/v2/stream/recentchange"})

############ REGEXES #################

ALL_REGEXES = [
    rb"evilbanana"
]
ALL_REGEXES = list(re.compile(pattern) for pattern in ALL_REGEXES)

############ CONFIG #################

ALLOWED_HTTP_METHODS = ["GET", "POST", "PATCH", "PUT", "DELETE"]
MAX_PARAMETER_AMOUNT = 20
MAX_PARAMETER_LENGTH = 200
USERAGENTS_WHITELIST = [
    r"CHECKER",
]
USERAGENTS_WHITELIST = [re.compile(pattern) for pattern in USERAGENTS_WHITELIST]
USERAGENTS_BLACKLIST = [
    r"requests",
    r"urllib",
    r"curl",
]
USERAGENTS_BLACKLIST = [re.compile(pattern) for pattern in USERAGENTS_BLACKLIST]
ACCEPT_ENCODING_WHITELIST = [
    "gzip, deflate, zstd",
]

############ FILTERS #################


def method_filter(ctx):
    if ctx.flow.type != "http":
        return

    method = ctx.flow.request.method.upper()

    if method not in ALLOWED_HTTP_METHODS:
        logger.debug(f"Invalid HTTP method")
        return replace_flag(ctx.flow)


def params_filter(ctx):
    if ctx.flow.type != "http":
        return

    params = ctx.flow.request.query

    if len(params) > MAX_PARAMETER_AMOUNT:
        logger.debug(f"Too many parameters: {len(params)}")
        return replace_flag(ctx.flow)

    for value in params.values():
        if len(value) > MAX_PARAMETER_LENGTH:
            logger.debug(f"Parameter too long: {len(value)}")
            return replace_flag(ctx.flow)


def nonprintable_params_filter(ctx):
    if ctx.flow.type != "http":
        return

    params = ctx.flow.request.query

    for param in params.values():
        for c in param:
            if c not in string.printable:
                logger.debug("Non-printable character found in parameter")
                return replace_flag(ctx.flow)


def useragent_whitelist_filter(ctx):
    if ctx.flow.type != "http":
        return

    user_agent = ctx.flow.request.headers.get("User-Agent", "")

    for pattern in USERAGENTS_WHITELIST:
        if re.search(pattern, user_agent):
            return

    logger.debug("Invalid User Agent detected")
    return replace_flag(ctx.flow)


def useragent_blacklist_filter(ctx):
    if ctx.flow.type != "http":
        return

    user_agent = ctx.flow.request.headers.get("User-Agent", "")

    for pattern in USERAGENTS_BLACKLIST:
        if re.search(pattern, user_agent):
            logger.debug("Blacklisted User Agent detected")
            return replace_flag(ctx.flow)


def accept_encoding_filter(ctx):
    if ctx.flow.type != "http":
        return

    accept_encoding = ctx.flow.request.headers.get("Accept-Encoding", "")

    if accept_encoding not in ACCEPT_ENCODING_WHITELIST:
        logger.debug(f"Invalid Accept-Encoding header")
        return replace_flag(ctx.flow)


def multiple_flags_filter(ctx):
    counter = 0

    if ctx.flow.type == "http" and ctx.flow.response:
        content = ctx.flow.response.content
        flags = re.findall(FLAG_REGEX, content)
        counter = len(flags)
    elif ctx.flow.type == "tcp":
        for msg in reversed(ctx.flow.messages):
            if not msg.from_client:
                content = msg.content
                flags = re.findall(FLAG_REGEX, content)
                counter += len(flags)

    if counter > 1:
        logger.debug(f"Multiple flags found: {counter}")
        return replace_flag(ctx.flow)


def regex_filter(ctx):
    for pattern in ALL_REGEXES:
        if re.search(pattern, ctx.raw_request):
            if ctx.session_id:
                logger.debug(f"[🔍] Regex match found in session {ctx.session_id}")
                ALL_SESSIONS[ctx.session_id] = True
            return replace_flag(ctx.flow)


def example_response_replace(ctx):
    flow = ctx.flow
    if flow.type == "http" and flow.response:
        flow.response.set_content(flow.response.content.replace(b"TO_REPLACE", b"PIPPO"))


FILTERS = [
    regex_filter,
    # method_filter,
    # params_filter,
    # nonprintable_params_filter,
    # useragent_whitelist_filter,
    # useragent_blacklist_filter,
    # accept_encoding_filter,
    # multiple_flags_filter,
]

# ------------------- CONTEXT AND FLOW REFERENCE -------------------
# https://docs.mitmproxy.org/stable/api/mitmproxy/flow.html
# https://docs.mitmproxy.org/stable/api/mitmproxy/http.html
# https://docs.mitmproxy.org/stable/api/mitmproxy/tcp.html

# ctx: FlowContext
#   - ctx.flow        → The mitmproxy flow object (http.HTTPFlow or tcp.TCPFlow)
#   - ctx.type        → "http" or "tcp"
#   - ctx.session_id  → Extracted session ID if available (e.g., from cookies)
#   - ctx.raw_request → Raw byte-string of request (headers + body)
#   - ctx.raw_response→ Raw byte-string of response (headers + body, if present)

# ctx.flow (when HTTP):
#   - flow.request.method / path / headers / query / raw_content
#   - flow.response.status_code / headers / raw_content

# ctx.flow (when TCP):
#   - flow.messages[] → list of TCPMessage objects
#       - .content (bytes), .from_client (bool)

# Used heavily by filters to inspect, match, and mutate traffic.
# -----------------------------------------------------------------


########### UTILITY FUNCTIONS ###########


def block_flow(flow):
    if flow.type == "http":
        flow.response = INFINITE_LOADING_RESPONSE
        # flow.response = ERROR_RESPONSE
        # flow.kill()
        return True
    elif flow.type == "tcp":
        if flow.killable:
            flow.kill()
            return True


def replace_flag(flow):
    if BLOCK_ALL_EVIL:
        if block_flow(flow):
            return
    if flow.type == "http":
        flow.response.set_content(re.sub(FLAG_REGEX, FLAG_REPLACEMENT.encode(), flow.response.content or b""))
    elif flow.type == "tcp":
        for msg in reversed(flow.messages):
            if not msg.from_client:
                msg.content = re.sub(FLAG_REGEX, FLAG_REPLACEMENT.encode(), msg.content)
                break


def find_session_id(flow):
    # Try to extract from Set-Cookie in response
    for h in flow.response.headers.get_all("Set-Cookie"):
        cookie = SimpleCookie()
        cookie.load(h)
        session_cookie = cookie.get(SESSION_COOKIE_NAME)
        if session_cookie:
            session_id = session_cookie.value
            if session_id not in ALL_SESSIONS:
                ALL_SESSIONS[session_id] = False
            logger.debug(f"Found session id in response header: {session_id}")
            return session_id

    # Try to extract from request cookies
    cookies = flow.request.cookies.get_all(SESSION_COOKIE_NAME)
    if cookies:
        session_id = cookies[0]
        if session_id not in ALL_SESSIONS:
            ALL_SESSIONS[session_id] = False
        logger.debug(f"Found session id in request cookies: {session_id}")
        return session_id
    else:
        logger.debug(f"No '{SESSION_COOKIE_NAME}' cookie found in request.")


##########################################
