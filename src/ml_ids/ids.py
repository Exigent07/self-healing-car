import can
import numpy as np
import threading
import time
import warnings
import os
import json
from hashlib import sha256
import google.generativeai as genai

from src.config.config_loader import CONFIG
from src.utils.logging_config import get_logger
from sklearn.exceptions import InconsistentVersionWarning

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

logger = get_logger("CAN_IDS_GATEWAY")

genai.configure(api_key=CONFIG.get("llm", "gemini_api_key"))
model = genai.GenerativeModel("models/gemini-2.0-flash")


class CanIDSGateway:
    def __init__(self, input_interface=None, output_interface=None, forward_log_path=None, post_eval_interval=None):
        self.input_interface = input_interface or CONFIG.get("ml_ids", "input_interface", default="vcan0")
        self.output_interface = output_interface or CONFIG.get("ml_ids", "output_interface", default="vcan1")
        self.forward_log_path = forward_log_path or CONFIG.get("ml_ids", "forward_log_path", default="logs/forwarded_packets.log")
        self.post_eval_interval = post_eval_interval or int(CONFIG.get("ml_ids", "post_eval_interval", default=5))
        self.running = False
        self.thread = None
        self.post_eval_thread = None

        try:
            self.input_bus = can.Bus(channel=self.input_interface, interface="socketcan")
            self.output_bus = can.Bus(channel=self.output_interface, interface="socketcan")
            logger.info(f"Listening on {self.input_interface}, forwarding to {self.output_interface}")
        except Exception as e:
            logger.error(f"Failed to initialize CAN buses: {e}")
            raise

    def _get_payload_data(self, msg):
        data = list(msg.data)
        while len(data) < 8:
            data.append(0)
        return data

    def _forward_packet(self, msg):
        try:
            can_id = msg.arbitration_id
            dlc = msg.dlc
            bytes_list = self._get_payload_data(msg)
            self.output_bus.send(msg)
            logger.info(f"{msg.timestamp},{can_id},{dlc},{','.join(map(str, bytes_list))}", extra={"is_forwarded_packet": True})
            logger.info(f"[{msg.timestamp:.3f}] ID={hex(can_id)} DLC={dlc} → FORWARDED")
        except Exception as e:
            logger.error(f"Error forwarding packet: {e}")

    def _listen(self):
        logger.info("Starting CAN gateway loop...")
        while self.running:
            msg = self.input_bus.recv(timeout=1.0)
            if msg:
                self._forward_packet(msg)

    def _post_evaluation_loop(self):
        logger.info("Started post-evaluation thread.")
        seen_hashes = set()

        while self.running:
            try:
                if not os.path.exists(self.forward_log_path):
                    time.sleep(self.post_eval_interval)
                    continue

                with open(self.forward_log_path, "r") as f:
                    lines = f.readlines()

                all_log_data = "\n".join(lines[-100:])

                for line in lines:
                    line = line.strip()
                    h = sha256(line.encode()).hexdigest()
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)

                    ts, can_id, dlc, *data = line.split(",")
                    can_id = int(can_id)
                    dlc = int(dlc)
                    payload = list(map(int, data))
                    prompt = f"""
Give a JSON report with these fields:
- id: the hex CAN ID
- payload: the bytes list
- threat_level: one of [safe, suspicious, dangerous]
- reason: one-line summary of the evaluation
- pattern: if any known attack pattern (e.g. fuzzing, replay, injection) is detected, specify it, otherwise null

CAN Packet:
ID: {hex(can_id)}
Payload: {payload}

Log Context:
{all_log_data}
"""
                    try:
                        gemini_response = model.generate_content(prompt)
                        response = gemini_response.text.strip()

                        if isinstance(response, list):
                            response = "".join(response)

                        if response.startswith("```json"):
                            response = response[7:]
                        if response.startswith("```"):
                            response = response[3:]
                        if response.endswith("```"):
                            response = response[:-3]

                        response = response.strip()

                        try:
                            result = json.loads(response)
                            if isinstance(result, list):
                                for item in result:
                                    if item.get("threat_level") == "dangerous":
                                        logger.critical(f"[{ts}] ⚠ Gemini flagged: {item}")
                                    elif item.get("threat_level") == "suspicious":
                                        logger.warning(f"[{ts}] ⚠ Gemini warning: {item}")
                            elif result.get("threat_level") == "dangerous":
                                logger.critical(f"[{ts}] ⚠ Gemini flagged: {result}")
                            elif result.get("threat_level") == "suspicious":
                                logger.warning(f"[{ts}] ⚠ Gemini warning: {result}")
                        except json.JSONDecodeError:
                            logger.error(f"Failed to parse Gemini response as JSON: {response}")
                    except Exception as llm_error:
                        logger.error(f"Gemini LLM error: {llm_error}")
            except Exception as e:
                logger.error(f"Post-evaluation error: {e}")

            time.sleep(self.post_eval_interval)

    def start(self):
        if self.running:
            logger.warning("Gateway already running.")
            return
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

        self.post_eval_thread = threading.Thread(target=self._post_evaluation_loop, daemon=True)
        self.post_eval_thread.start()

        logger.info("CAN IDS Gateway started.")

    def stop(self):
        if not self.running:
            logger.warning("Gateway already stopped.")
            return
        self.running = False
        self.thread.join()
        self.post_eval_thread.join()
        logger.info("CAN IDS Gateway stopped.")


if __name__ == "__main__":
    gateway = CanIDSGateway()
    try:
        gateway.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        gateway.stop()
        