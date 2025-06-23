########## FILTER SECTION ##########

def banana_rule(flow):
    print(flow.messages)
    for msg in flow.messages:
        if msg.from_client and b"banana" in msg.content:
            print(f"[🔍] banana_rule triggered on:\n{msg.content}")
            for res in flow.messages:
                if not res.from_client and b"world" in res.content:
                    res.content = res.content.replace(b"world", b"PALLE")
                    print("[✏️] Replaced 'world' with 'PALLE'")
            break

FILTERS = [banana_rule]

########## END FILTER SECTION ##########

from mitmproxy import tcp

class ProxyAddon:
    def __init__(self):
        print("[🔧] ProxyAddon reloaded")

    def tcp_message(self, flow: tcp.TCPFlow):
        print(f"[📥] TCP message received ({len(flow.messages)} total messages)")

        try:
            for f in FILTERS:
                f(flow)
        except Exception as e:
            print(f"[❌] Error in filter: {e}")

addons = [ProxyAddon()]
