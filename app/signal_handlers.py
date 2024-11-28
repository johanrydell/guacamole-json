import logging
import signal
import sys

logger = logging.getLogger(__name__)


def setup_signal_handlers():
    def cleanup_and_exit(*args):
        logger.info("Shutting down gracefully.")
        logger.info("Flushing logs and cleaning up resources.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)
