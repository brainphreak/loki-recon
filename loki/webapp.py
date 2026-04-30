#webapp.py

import sys
import os
import json
import threading
import http.server
import socketserver
import logging
import signal
import gzip
import io
import secrets
import time
from queue import Empty
from logger import Logger
from init_shared import shared_data
from utils import WebUtils
from display import broker as display_broker

# ---- Bearer token for /api/v1/* (additive auth, original UI stays open) ----
_API_TOKEN_FILE = os.path.join(
    getattr(shared_data, 'state_dir', getattr(shared_data, 'datadir', '.')),
    'api_token.json',
)


def _load_or_create_token() -> str:
    try:
        if os.path.exists(_API_TOKEN_FILE):
            with open(_API_TOKEN_FILE, 'r') as f:
                tok = json.load(f).get('token')
            if tok:
                return tok
        os.makedirs(os.path.dirname(_API_TOKEN_FILE), exist_ok=True)
        tok = secrets.token_urlsafe(32)
        with open(_API_TOKEN_FILE, 'w') as f:
            json.dump({'token': tok}, f)
        try:
            os.chmod(_API_TOKEN_FILE, 0o600)
        except Exception:
            pass
        return tok
    except Exception:
        # Fallback: ephemeral in-memory token (regenerated on each boot).
        return secrets.token_urlsafe(32)


API_TOKEN: str = _load_or_create_token()
print(f"loki-pi API token: {API_TOKEN}")
print(f"   (saved to {_API_TOKEN_FILE})")

# Initialize the logger
logger = Logger(name="webapp.py", level=logging.INFO)

# Set the path to the favicon
favicon_path = os.path.join(shared_data.webdir, 'images', 'favicon.ico')

# Create a single shared WebUtils instance (not per-request)
# This prevents reimporting all action modules on every HTTP request
_web_utils = WebUtils(shared_data, logger)

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.shared_data = shared_data
        self.web_utils = _web_utils  # Use shared instance
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        # Suppress chatty 200 GETs but include the path on errors so 404s
        # are diagnosable instead of just "code 404, message File not found".
        rendered = format % args
        if 'GET' in rendered:
            return
        path_hint = f" path={getattr(self, 'path', '?')}"
        logger.info("%s - - [%s] %s%s\n" %
                    (self.client_address[0],
                     self.log_date_time_string(),
                     rendered,
                     path_hint))

    def gzip_encode(self, content):
        """Gzip compress the given content."""
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=out, mode="w") as f:
            f.write(content)
        return out.getvalue()

    def send_gzipped_response(self, content, content_type):
        """Send HTTP response (gzip disabled due to header issues)."""
        # Note: gzip was causing issues - Content-Encoding header wasn't being sent
        # Serving uncompressed content for now
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def serve_file_gzipped(self, file_path, content_type):
        """Serve a file (without gzip for now)."""
        with open(file_path, 'rb') as file:
            content = file.read()
        self.send_gzipped_response(content, content_type)

    # HTML pages that should all serve the SPA index.html
    SPA_PAGES = {'/', '/index.html', '/config.html', '/actions.html', '/network.html',
                 '/netkb.html', '/loki.html', '/loot.html', '/credentials.html', '/manual.html'}

    def serve_sse_events(self):
        """SSE stream of display broker events. Replays buffered history then streams live."""
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
        except Exception:
            return

        q = display_broker.subscribe()
        last_keepalive = time.time()
        try:
            while not self.shared_data.webapp_should_exit:
                try:
                    event = q.get(timeout=1.0)
                except Empty:
                    if time.time() - last_keepalive > 15:
                        try:
                            self.wfile.write(b": keepalive\n\n")
                            self.wfile.flush()
                            last_keepalive = time.time()
                        except (BrokenPipeError, ConnectionResetError):
                            break
                    continue

                payload = (
                    f"id: {event.get('id', 0)}\n"
                    f"event: {event.get('type', 'message')}\n"
                    f"data: {json.dumps(event)}\n\n"
                )
                try:
                    self.wfile.write(payload.encode("utf-8"))
                    self.wfile.flush()
                    last_keepalive = time.time()
                except (BrokenPipeError, ConnectionResetError):
                    break
                except Exception as e:
                    logger.debug(f"SSE write error: {e}")
                    break
        finally:
            display_broker.unsubscribe(q)

    def _require_api_v1_auth(self) -> bool:
        """Return True if the request is allowed; otherwise send 401 and return False.

        Only enforced for /api/v1/*. Original UI routes stay open so the
        existing JS keeps working without code changes.
        """
        if not self.path.startswith('/api/v1/'):
            return True
        # /api/v1/events also accepts ?token= for EventSource (no header support).
        provided = ''
        auth_header = self.headers.get('Authorization', '')
        if auth_header.lower().startswith('bearer '):
            provided = auth_header[7:].strip()
        elif '?' in self.path:
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            provided = (qs.get('token') or [''])[0]
        if provided and secrets.compare_digest(provided, API_TOKEN):
            return True
        body = json.dumps({'error': 'unauthorized', 'hint': 'Authorization: Bearer <token>'}).encode('utf-8')
        self.send_response(401)
        self.send_header('Content-Type', 'application/json')
        self.send_header('WWW-Authenticate', 'Bearer realm="loki-pi"')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        return False

    def do_GET(self):
        if not self._require_api_v1_auth():
            return
        # Handle GET requests. Serve the SPA shell for all page URLs.
        if self.path in self.SPA_PAGES:
            self.serve_file_gzipped(os.path.join(self.shared_data.webdir, 'index.html'), 'text/html')
        elif self.path == '/events' or self.path == '/api/v1/events':
            self.serve_sse_events()
        elif self.path == '/api/stats':
            self.web_utils.serve_stats(self)
        elif self.path == '/api/vulnerabilities':
            self.web_utils.serve_vulnerabilities(self)
        elif self.path.startswith('/api/host_loot_summary/'):
            ip = self.path.split('/api/host_loot_summary/')[1]
            self.web_utils.serve_host_loot_summary(self, ip)
        elif self.path.startswith('/api/vulnerabilities/'):
            ip = self.path.split('/api/vulnerabilities/')[1]
            self.web_utils.serve_vulnerability_detail(self, ip)
        elif self.path == '/api/theme':
            self.web_utils.serve_theme(self)
        elif self.path == '/api/themes':
            self.web_utils.serve_themes_list(self)
        elif self.path == '/api/theme_font':
            self.web_utils.serve_theme_font(self)

        # ----- /api/v1/* additive JSON namespace (for scripts + future apps) -----
        elif self.path == '/api/v1/status':
            self.web_utils.serve_stats(self)
        elif self.path == '/api/v1/targets':
            self.web_utils.serve_netkb_data_json(self)
        elif self.path == '/api/v1/credentials':
            self.web_utils.serve_credentials_data(self)
        elif self.path.startswith('/api/v1/exfil'):
            self.web_utils.list_files_endpoint(self)
        elif self.path == '/api/v1/themes':
            self.web_utils.serve_themes_list(self)
        elif self.path == '/api/v1/networks':
            self.web_utils.get_available_networks(self)
        elif self.path == '/load_config':
            self.web_utils.serve_current_config(self)
        elif self.path == '/restore_default_config':
            self.web_utils.restore_default_config(self)
        elif self.path == '/get_web_delay':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = json.dumps({"web_delay": self.shared_data.web_delay})
            self.wfile.write(response.encode('utf-8'))
        elif self.path == '/scan_wifi':
            # WiFi management skipped on Pager
            self.send_response(501)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "WiFi management not available on Pager"}')
        elif self.path == '/network_data':
            self.web_utils.serve_network_data(self)
        elif self.path == '/netkb_data':
            self.web_utils.serve_netkb_data(self)
        elif self.path == '/netkb_data_json':
            self.web_utils.serve_netkb_data_json(self)
        elif self.path == '/get_networks':
            self.web_utils.get_available_networks(self)
        elif self.path.startswith('/screen.png'):
            self.web_utils.serve_image(self)
        elif self.path == '/favicon.ico':
            self.web_utils.serve_favicon(self)
        elif self.path == '/manifest.json':
            self.web_utils.serve_manifest(self)
        elif self.path == '/apple-touch-icon':
            self.web_utils.serve_apple_touch_icon(self)
        elif self.path.startswith('/get_logs'):
            # Parse query parameters for filtering
            current_action_only = False
            since_timestamp = None
            if '?' in self.path:
                from urllib.parse import parse_qs, urlparse, unquote
                query = parse_qs(urlparse(self.path).query)
                current_action_only = query.get('current', ['0'])[0] == '1'
                since_param = query.get('since', [None])[0]
                if since_param:
                    since_timestamp = unquote(since_param)
            self.web_utils.serve_logs(self, current_action_only=current_action_only, since_timestamp=since_timestamp)
        elif self.path == '/list_credentials':
            self.web_utils.serve_credentials_data(self)
        elif self.path == '/download_credentials':
            self.web_utils.download_credentials(self)
        elif self.path.startswith('/list_files'):
            self.web_utils.list_files_endpoint(self)
        elif self.path.startswith('/download_file'):
            self.web_utils.download_file(self)
        elif self.path.startswith('/api/export_host/'):
            ip = self.path.split('/api/export_host/')[1]
            self.web_utils.export_host_report(self, ip)
        elif self.path.startswith('/download_backup'):
            self.web_utils.download_backup(self)
        elif self.path == '/list_logs':
            self.web_utils.list_logs_endpoint(self)
        elif self.path.startswith('/download_log'):
            self.web_utils.download_log(self)
        else:
            super().do_GET()

    def do_POST(self):
        if not self._require_api_v1_auth():
            return
        # Handle POST requests for saving configuration, connecting to Wi-Fi, clearing files, rebooting, and shutting down.
        if self.path == '/save_config':
            self.web_utils.save_configuration(self)
        elif self.path == '/api/theme':
            self.web_utils.set_theme(self)

        # ----- /api/v1/* additive JSON namespace -----
        elif self.path == '/api/v1/theme':
            self.web_utils.set_theme(self)
        elif self.path == '/api/v1/scan':
            self.web_utils.api_v1_scan(self)
        elif self.path == '/api/v1/targets/clear':
            self.web_utils.clear_hosts(self)
        elif self.path == '/connect_wifi':
            # WiFi management skipped on Pager
            self.send_response(501)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "WiFi management not available on Pager"}')
        elif self.path == '/disconnect_wifi':
            # WiFi management skipped on Pager
            self.send_response(501)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "WiFi management not available on Pager"}')
        elif self.path == '/clear_files':
            self.web_utils.clear_files(self)
        elif self.path == '/clear_files_light':
            self.web_utils.clear_files_light(self)
        elif self.path == '/initialize_csv':
            self.web_utils.initialize_csv(self)
        elif self.path == '/reboot':
            self.web_utils.reboot_system(self)
        elif self.path == '/shutdown':
            self.web_utils.shutdown_system(self)
        elif self.path == '/restart_loki_service':
            self.web_utils.restart_loki_service(self)
        elif self.path == '/backup':
            self.web_utils.backup(self)
        elif self.path == '/restore':
            self.web_utils.restore(self)
        elif self.path == '/stop_orchestrator':  # New route to stop the orchestrator
            self.web_utils.stop_orchestrator(self)
        elif self.path == '/start_orchestrator':  # New route to start the orchestrator
            self.web_utils.start_orchestrator(self)
        elif self.path == '/execute_manual_attack':  # New route to execute a manual attack
            self.web_utils.execute_manual_attack(self)
        elif self.path == '/clear_hosts':  # Clear discovered hosts to start fresh
            self.web_utils.clear_hosts(self)
        elif self.path == '/clear_scan_logs':
            self.web_utils.clear_scan_logs(self)
        elif self.path == '/clear_stats':
            self.web_utils.clear_stats(self)
        elif self.path == '/clear_stolen_files':
            self.web_utils.clear_stolen_files(self)
        elif self.path == '/clear_credentials':
            self.web_utils.clear_credentials(self)
        elif self.path == '/clear_all':
            self.web_utils.clear_all(self)
        elif self.path == '/stop_manual_attack':  # Stop running manual attack without touching orchestrator
            self.web_utils.stop_manual_attack(self)
        elif self.path == '/mark_action_start':  # Mark action start time for log filtering
            self.web_utils.mark_action_start(self)
        elif self.path == '/add_manual_target':  # Add custom IP/hostname to netkb
            self.web_utils.add_manual_target(self)
        elif self.path == '/api/terminal':
            self.web_utils.execute_terminal_command(self)
        elif self.path == '/api/update_kev':
            self.web_utils.update_kev_catalog(self)
        else:
            self.send_response(404)
            self.end_headers()

class WebThread(threading.Thread):
    """
    Thread to run the web server serving the EPD display interface.
    """
    def __init__(self, handler_class=CustomHandler, port=None, bind=None):
        super().__init__()
        self.shared_data = shared_data
        self.port = port if port is not None else int(os.environ.get('LOKI_PORT', '8000'))
        self.bind = bind if bind is not None else os.environ.get('LOKI_BIND', '')
        self.handler_class = handler_class
        self.httpd = None

    def run(self):
        """
        Run the web server in a separate thread.
        """
        while not self.shared_data.webapp_should_exit:
            try:
                # Create threaded server with SO_REUSEADDR to allow quick restart
                # ThreadingTCPServer handles each request in a separate thread for responsiveness
                socketserver.ThreadingTCPServer.allow_reuse_address = True
                with socketserver.ThreadingTCPServer((self.bind, self.port), self.handler_class) as httpd:
                    self.httpd = httpd
                    logger.info(f"Serving at port {self.port}")
                    while not self.shared_data.webapp_should_exit:
                        httpd.handle_request()
            except OSError as e:
                # Handle address in use - errno 98 (Linux) or 125 (some embedded systems)
                if e.errno in (98, 125, 48):  # EADDRINUSE varies by platform
                    logger.warning(f"Port {self.port} is in use, trying the next port...")
                    self.port += 1
                else:
                    logger.error(f"Error in web server: {e}")
                    break
            finally:
                if self.httpd:
                    self.httpd.server_close()
                    logger.info("Web server closed.")

    def shutdown(self):
        """
        Shutdown the web server gracefully.
        """
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            logger.info("Web server shutdown initiated.")

def handle_exit_web(signum, frame):
    """
    Handle exit signals to shutdown the web server cleanly.
    """
    shared_data.webapp_should_exit = True
    if web_thread.is_alive():
        web_thread.shutdown()
        web_thread.join()  # Wait until the web_thread is finished
    logger.info("Server shutting down...")
    sys.exit(0)

# Initialize the web thread
web_thread = WebThread()

if __name__ == "__main__":
    # Only register signal handlers when running standalone
    # (when imported by Bjorn.py, it sets its own handlers)
    signal.signal(signal.SIGINT, handle_exit_web)
    signal.signal(signal.SIGTERM, handle_exit_web)

    try:
        # Start the web server thread
        web_thread.start()
        logger.info("Web server thread started.")
    except Exception as e:
        logger.error(f"An exception occurred during web server start: {e}")
        handle_exit_web(signal.SIGINT, None)
        sys.exit(1)
