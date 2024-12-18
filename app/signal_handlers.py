import logging
import signal
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class GracefulExit(SystemExit):
    """Custom exception for graceful exits triggered by signals."""


def setup_signal_handlers(custom_cleanup: Optional[Callable[[], None]] = None):
    """
    Sets up signal handlers for SIGINT and SIGTERM to ensure graceful shutdown.

    Args:
        custom_cleanup (Optional[Callable[[], None]]): A custom cleanup function
        to be executed before exiting. Defaults to None.
    """

    def cleanup_and_exit(signum, frame):
        """
        Handles termination signals by performing cleanup and exiting gracefully.

        Args:
            signum (int): Signal number.
            frame (FrameType): Current stack frame (unused).
        """
        try:
            logger.info(f"Received signal {signum}. Initiating shutdown...")
            if custom_cleanup:
                logger.info("Executing custom cleanup logic.")
                custom_cleanup()
            logger.info("Flushing logs and cleaning up resources.")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)
        finally:
            logger.info("Raising GracefulExit exception.")
            raise GracefulExit()

    # Register signal handlers
    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    logger.info("Signal handlers for SIGINT and SIGTERM are set.")
