from src.data_collection import collector
from src.ml_ids import detector
from src.recovery_system import responder
from src.ota_updater import updater
from src.ssl_communication import secure_channel
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

def main():
  logger.info("🚗 Self-Healing Car System Booting...")
  collector.collect_data()
  intrusions = detector.run_detection()
  if intrusions:
    responder.auto_recover(intrusions)
  updater.check_and_apply_updates()
  secure_channel.establish_ssl()

if __name__ == "__main__":
  main()