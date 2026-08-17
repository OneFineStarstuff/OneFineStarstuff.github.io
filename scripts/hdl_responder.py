import time

def main():
    """Simulates the Human-in-the-Loop (HDL) responding to an escalation."""
    print("Initializing Human-in-the-Loop (HDL) Responder...")
    print("Waiting for escalations from the SCP...")
    print("----------------------------------------------------------")

    # In a real system, this would be a message queue or API call.
    # Here, we simulate by waiting for user input.
    input("Press Enter to simulate receiving an escalation from the SCP...")

    # Simulate the data received from the SCP
    escalated_transaction = {
        "transaction_id": 67890,
        "model_score": 0.97,
        "protected_attribute_group": 'B',
        "timestamp": time.ctime()
    }

    print("\n***ESCALATION RECEIVED***")
    print(f"Incident Time: {escalated_transaction['timestamp']}")
    print(f"Transaction ID: {escalated_transaction['transaction_id']}")
    print(f"Model Score: {escalated_transaction['model_score']:.2f} (Breached Policy: > 0.95)")
    print(f"Protected Group: {escalated_transaction['protected_attribute_group']}")
    print("----------------------------------------------------------\n")

    print("Analyst Decision Required:")
    print("1. Approve Transaction (Override Policy)")
    print("2. Reject Transaction (Uphold Policy)")
    print("3. Flag for Further Review")

    decision = ""
    while decision not in ['1', '2', '3']:
        decision = input("Enter your decision (1, 2, or 3): ")

    log_decision(escalated_transaction, decision)

    print("\nDecision logged. The system has been updated.")
    print("HDL process complete.")

def log_decision(transaction_data, decision):
    """Logs the analyst's decision to a file."""
    log_file = "hdl_decision_log.txt"
    decision_map = {
        '1': "Approved (Override)",
        '2': "Rejected (Uphold)",
        '3': "Flagged for Review"
    }
    log_entry = f"Timestamp: {time.ctime()}, Transaction: {transaction_data['transaction_id']}, Score: {transaction_data['model_score']:.2f}, Decision: {decision_map[decision]}\n"

    with open(log_file, "a") as f:
        f.write(log_entry)

if __name__ == "__main__":
    main()
