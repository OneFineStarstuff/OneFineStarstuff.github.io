import time
import random
import collections

# --- Simulation Components ---

def simulate_data_stream():
    """Generates a simulated stream of model predictions. Includes occasional anomalies."""
    anomaly_counter = 0
    is_anomaly = False

    while True:
        # Introduce a statistical drift anomaly every 30-50 data points
        if not is_anomaly and random.randint(1, 40) == 1:
            is_anomaly = True
            anomaly_counter = 10  # Anomaly lasts for 10 data points
            print("\n--- Anomaly Introduced into Data Stream ---")

        if is_anomaly:
            # During an anomaly, model scores are consistently higher
            score = random.uniform(0.7, 0.9)
            anomaly_counter -= 1
            if anomaly_counter <= 0:
                is_anomaly = False
                print("--- Anomaly Ceased in Data Stream ---\n")
        else:
            # Normal operation
            score = random.uniform(0.2, 0.6)

        yield {
            "transaction_id": random.randint(10000, 99999),
            "model_score": score,
        }
        time.sleep(0.5)

# --- Perseus Engine Logic ---

class PerseusEngine:
    def __init__(self, window_size=20, threshold=0.2):
        """
        Initializes the Perseus Engine.

        Args:
            window_size: The number of recent data points to consider for the moving average.
            threshold: The deviation from the moving average that triggers an alert.
        """
        self.window = collections.deque(maxlen=window_size)
        self.window_size = window_size
        self.threshold = threshold
        self.moving_average = None

    def analyze(self, data_point):
        """Analyzes a single data point for statistical anomalies."""
        score = data_point['model_score']
        self.window.append(score)

        # Don't start analyzing until the window is full
        if len(self.window) < self.window_size:
            return

        new_moving_average = sum(self.window) / self.window_size

        if self.moving_average is not None:
            deviation = abs(new_moving_average - self.moving_average)
            if deviation > self.threshold:
                print(f"\n***PERSEUS ALERT: Statistical Anomaly Detected!***")
                print(f"Cause: Moving average shifted by {deviation:.2f}, exceeding threshold of {self.threshold}.")
                print(f"Previous Average: {self.moving_average:.2f}, New Average: {new_moving_average:.2f}")
                print(f"This suggests a potential model drift or a targeted attack.")
                print("----------------------------------------------------------\n")

        self.moving_average = new_moving_average
        print(f"Analyzed transaction {data_point['transaction_id']}. Current Moving Average: {self.moving_average:.2f}")

def main():
    """Simulates the Perseus Engine monitoring for statistical anomalies."""
    print("Initializing Perseus Anomaly Detection Engine...")
    print(f"Analyzing data stream for significant statistical deviations.")
    print("----------------------------------------------------------")

    engine = PerseusEngine()
    data_stream = simulate_data_stream()

    for data_point in data_stream:
        engine.analyze(data_point)

if __name__ == "__main__":
    main()
