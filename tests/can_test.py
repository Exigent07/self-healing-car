import can

# Create a CAN message
msg = can.Message(
    arbitration_id=0x321,  # Assume this is a common ID used for engine RPM
    data=[0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64],  # Redundant or illogical
    is_extended_id=False
)


# Open the CAN bus (change 'vcan0' to your actual interface if needed)
try:
    bus = can.interface.Bus(channel='vcan0', interface='socketcan')
    bus.send(msg)
    print(f"Sent: ID={hex(msg.arbitration_id)} Data={msg.data}")
except can.CanError as e:
    print(f"Failed to send CAN message: {e}")

