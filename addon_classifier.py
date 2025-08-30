from mitmproxy import http

class ClassifierAddon:
    def __init__(self):
        self.apps = {}

    def request(self, flow: http.HTTPFlow):
        if flow.server_conn.cert is None:
            self.apps.setdefault(flow.client_conn.address, []).append("No Pinning")
        else:
            self.apps.setdefault(flow.client_conn.address, []).append("Possible Pinning")

addons = [ClassifierAddon()]
