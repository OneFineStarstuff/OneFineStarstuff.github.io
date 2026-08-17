import time
import random

def simulate_data_stream():
    """Generates a simulated stream of model predictions."""
    while True:
        yield {
            "transaction_id": random.randint(10000, 99999),
            "model_score": random.uniform(0.0, 1.0),
            "protected_attribute_group": random.choice(['A', 'B', 'C'])
        }
        time.sleep(0.5)

def main():
    """Simulates the SCP monitoring for a simple policy violation."""
    print("Initializing Supervisory Control Plane (SCP) Monitor...")
    print("Policy: Alert if model_score > 0.95 for any transaction.")
    print("----------------------------------------------------------")

    data_stream = simulate_data_stream()

    for data_point in data_stream:
        print(f"Checking transaction {data_point['transaction_id']}: Score = {data_point['model_score']:.2f}")
        if data_point['model_score'] > 0.95:
            print("\n***POLICY VIOLATION ALERT!***")
            print(f"Transaction {data_point['transaction_id']} triggered an alert.")
            print("Escalating to Human-in-the-Loop (HDL) System.")
            print("----------------------------------------------------------\n")

if __name__ == "__main__":
    main()
