import signal

from app.signal_handlers import setup_signal_handlers


def test_signal_handler_basic(mocker):
    mock_exit = mocker.patch("sys.exit")
    mock_logger = mocker.patch("app.signal_handlers.logger.info")

    setup_signal_handlers()

    # Simulate SIGINT
    signal.getsignal(signal.SIGINT)(signal.SIGINT, None)

    # Assert that the exit and logs were called
    mock_exit.assert_called_once_with(0)
    mock_logger.assert_any_call("Received signal 2. Initiating shutdown...")


def test_signal_handler_with_custom_cleanup(mocker):
    mock_exit = mocker.patch("sys.exit")
    mock_logger = mocker.patch("app.signal_handlers.logger.info")
    mock_cleanup = mocker.Mock()

    setup_signal_handlers(custom_cleanup=mock_cleanup)

    # Simulate SIGTERM
    signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

    # Assert custom cleanup was called
    mock_cleanup.assert_called_once()
    mock_exit.assert_called_once_with(0)
    mock_logger.assert_any_call("Executing custom cleanup logic.")
