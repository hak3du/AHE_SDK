from logger import logger

def shorten_bytes_for_display(data: bytes, length=10):
    try:
        if len(data) <= length:
            result = data.hex()
            logger.info(f"Shortened bytes for display (full): {result}")
            return result
        result = data[:length].hex() + "..."
        logger.info(f"Shortened bytes for display (truncated): {result}")
        return result
    except Exception as e:
        logger.error(f"Error in shorten_bytes_for_display: {e}", exc_info=True)
        return ""