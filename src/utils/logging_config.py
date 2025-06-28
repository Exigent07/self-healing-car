import logging
import os
import colorlog

class ForwardedPacketFilter(logging.Filter):
    def filter(self, record):
        return getattr(record, "is_forwarded_packet", False)

def get_logger(name):
    if not os.path.exists("logs"):
        os.makedirs("logs")

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler("logs/system.log")
    fh.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(file_fmt)

    fwd = logging.FileHandler("logs/forwarded_packets.log")
    fwd.setLevel(logging.INFO)
    fwd.setFormatter(logging.Formatter('%(message)s'))
    fwd.addFilter(ForwardedPacketFilter())

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "cyan", "INFO": "green", "WARNING": "yellow",
            "ERROR": "red", "CRITICAL": "bold_red"
        }
    ))

    if not logger.handlers:
        logger.addHandler(fh)
        logger.addHandler(fwd)
        logger.addHandler(ch)

    return logger
