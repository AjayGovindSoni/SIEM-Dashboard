import socketserver
import threading
import logging
from datetime import datetime
from typing import Callable, Optional
from log_parser import LogParserFactory

logger = logging.getLogger(__name__)


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Handler for UDP syslog messages"""
    
    def handle(self):
        data = self.request[0].strip()
        
        try:
            log_line = data.decode('utf-8')
            if self.server.callback:
                self.server.callback(log_line)
        except Exception as e:
            logger.error(f"Error handling UDP syslog: {e}")


class SyslogTCPHandler(socketserver.StreamRequestHandler):
    """Handler for TCP syslog messages"""
    
    def handle(self):
        try:
            for line in self.rfile:
                log_line = line.strip().decode('utf-8')
                if log_line and self.server.callback:
                    self.server.callback(log_line)
        except Exception as e:
            logger.error(f"Error handling TCP syslog: {e}")


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Threaded UDP server"""
    pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server"""
    allow_reuse_address = True


class SyslogReceiver:
    """Syslog receiver that listens on UDP and TCP ports"""
    
    def __init__(self, udp_port: int = 5514, tcp_port: int = 5515,
                 callback: Optional[Callable] = None):
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.callback = callback
        self.udp_server = None
        self.tcp_server = None
        self.udp_thread = None
        self.tcp_thread = None
        self.running = False
        
    def start(self):
        """Start listening for syslog messages"""
        if self.running:
            logger.warning("Syslog receiver already running")
            return
        
        try:
            # Start UDP server
            self.udp_server = ThreadedUDPServer(('0.0.0.0', self.udp_port), SyslogUDPHandler)
            self.udp_server.callback = self.callback
            self.udp_thread = threading.Thread(target=self.udp_server.serve_forever)
            self.udp_thread.daemon = True
            self.udp_thread.start()
            logger.info(f"Syslog UDP receiver started on port {self.udp_port}")
            
            # Start TCP server
            self.tcp_server = ThreadedTCPServer(('0.0.0.0', self.tcp_port), SyslogTCPHandler)
            self.tcp_server.callback = self.callback
            self.tcp_thread = threading.Thread(target=self.tcp_server.serve_forever)
            self.tcp_thread.daemon = True
            self.tcp_thread.start()
            logger.info(f"Syslog TCP receiver started on port {self.tcp_port}")
            
            self.running = True
            
        except Exception as e:
            logger.error(f"Failed to start syslog receiver: {e}")
            self.stop()
    
    def stop(self):
        """Stop the syslog receivers"""
        if not self.running:
            return
        
        if self.udp_server:
            self.udp_server.shutdown()
            self.udp_server.server_close()
            logger.info("Syslog UDP receiver stopped")
        
        if self.tcp_server:
            self.tcp_server.shutdown()
            self.tcp_server.server_close()
            logger.info("Syslog TCP receiver stopped")
        
        self.running = False


class LogFileMonitor:
    """Monitor log files for new entries"""
    
    def __init__(self, file_paths: list, callback: Optional[Callable] = None,
                 parser_format: str = 'auto'):
        self.file_paths = file_paths
        self.callback = callback
        self.parser = LogParserFactory.get_parser(parser_format)
        self.running = False
        self.threads = []
        
    def start(self):
        """Start monitoring log files"""
        if self.running:
            return
        
        self.running = True
        
        for file_path in self.file_paths:
            thread = threading.Thread(target=self._monitor_file, args=(file_path,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
            logger.info(f"Started monitoring file: {file_path}")
    
    def stop(self):
        """Stop monitoring log files"""
        self.running = False
        logger.info("Stopped log file monitoring")
    
    def _monitor_file(self, file_path: str):
        """Monitor a single log file"""
        try:
            with open(file_path, 'r') as f:
                # Seek to end of file
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    
                    if line:
                        line = line.strip()
                        if line and self.callback:
                            self.callback(line)
                    else:
                        # No new line, wait a bit
                        threading.Event().wait(0.1)
                        
        except FileNotFoundError:
            logger.error(f"Log file not found: {file_path}")
        except Exception as e:
            logger.error(f"Error monitoring file {file_path}: {e}")


class LogIngestionManager:
    """Manages all log ingestion sources"""
    
    def __init__(self, event_callback: Callable):
        self.event_callback = event_callback
        self.syslog_receiver = None
        self.file_monitors = []
        self.parser = LogParserFactory.get_parser('auto')
        
    def start_syslog_receiver(self, udp_port: int = 5514, tcp_port: int = 5515):
        """Start syslog receiver"""
        self.syslog_receiver = SyslogReceiver(
            udp_port=udp_port,
            tcp_port=tcp_port,
            callback=self._handle_log_line
        )
        self.syslog_receiver.start()
    
    def add_file_monitor(self, file_paths: list, parser_format: str = 'auto'):
        """Add log file monitor"""
        monitor = LogFileMonitor(
            file_paths=file_paths,
            callback=self._handle_log_line,
            parser_format=parser_format
        )
        monitor.start()
        self.file_monitors.append(monitor)
    
    def stop_all(self):
        """Stop all ingestion sources"""
        if self.syslog_receiver:
            self.syslog_receiver.stop()
        
        for monitor in self.file_monitors:
            monitor.stop()
    
    def _handle_log_line(self, log_line: str):
        """Parse log line and pass to event callback"""
        try:
            parsed_event = self.parser.parse(log_line)
            if parsed_event and self.event_callback:
                self.event_callback(parsed_event)
        except Exception as e:
            logger.error(f"Error parsing log line: {e}")
            logger.debug(f"Failed log line: {log_line[:200]}")


if __name__ == "__main__":
    # Test syslog receiver
    logging.basicConfig(level=logging.INFO)
    
    def test_callback(log_line):
        print(f"Received: {log_line[:100]}")
    
    receiver = SyslogReceiver(callback=test_callback)
    receiver.start()
    
    try:
        print("Syslog receiver running. Press Ctrl+C to stop.")
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        receiver.stop()
