import logging
import os
import signal
from typing import Callable, Optional

logger = logging.getLogger(__name__)


def setup_signal_handlers(custom_cleanup: Optional[Callable[[], None]] = None):
    """
    Sets up fast signal handlers for SIGINT and SIGTERM.
    """

    def fast_shutdown(signum, frame):
        """
        Immediately shuts down the service without unnecessary delays.
        """
        logger.info(f"Received signal {signal.Signals(signum).name}. Shutting down...")

        # Run cleanup if provided
        if custom_cleanup:
            try:
                logger.info("Running cleanup...")
                custom_cleanup()
            except Exception as e:
                logger.exception(f"Cleanup error: {e}")

        # Flush logs to prevent missing messages
        logging.shutdown()

        # Fastest way to exit (no Python exception handling overhead)
        os._exit(0)  # Hard exit

    # Register handlers for fast shutdown
    signal.signal(signal.SIGINT, fast_shutdown)
    signal.signal(signal.SIGTERM, fast_shutdown)

    logger.info("Fast shutdown signal handlers set up.")
