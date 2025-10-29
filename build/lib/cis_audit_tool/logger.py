import logging

def setup_logger(debug=False):
    """Set up logging."""
    logger = logging.getLogger("cis_audit_tool")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger