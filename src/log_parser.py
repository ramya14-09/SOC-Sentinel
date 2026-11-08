import pandas as pd
import ipaddress

# Required columns in the authentication dataset
REQUIRED_COLUMNS = [
    "timestamp",
    "user_id",
    "ip_address",
    "event_type",
    "status"
]


def load_logs(file_path):
    """
    Read and validate authentication logs from a CSV file.
    """

    # Check whether the file exists and read it
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Dataset not found: {file_path}"
        )

    # Remove extra spaces from column names
    df.columns = df.columns.str.strip()

    # Check required columns
    missing_columns = [
        col for col in REQUIRED_COLUMNS
        if col not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing columns: {missing_columns}"
        )

    # Keep only the required columns
    df = df[REQUIRED_COLUMNS].copy()

    # Remove extra spaces from text values
    for col in ["user_id", "ip_address",
                "event_type", "status"]:
        df[col] = df[col].astype("string").str.strip()

    # Convert timestamps into datetime format
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce"
    )

    # Standardise text values
    df["status"] = df["status"].str.upper()
    df["event_type"] = df["event_type"].str.upper()

    # Validate IP addresses
    def is_valid_ip(ip):
        try:
            ipaddress.ip_address(str(ip))
            return True
        except ValueError:
            return False

    valid_ip = df["ip_address"].apply(is_valid_ip)

    # Remove invalid and incomplete records
    df = df.dropna(
        subset=["timestamp", "user_id",
                "ip_address", "event_type", "status"]
    )

    df = df[valid_ip.loc[df.index]]

    # Keep only supported authentication records
    df = df[
        (df["event_type"] == "LOGIN") &
        (df["status"].isin(["SUCCESS", "FAILED"]))
    ]

    # Sort records chronologically
    df = df.sort_values("timestamp").reset_index(drop=True)

    return df


# Run this module directly to test log processing
if __name__ == "__main__":

    logs = load_logs("data/sample_auth_logs.csv")

    print("\nSOC SENTINEL - LOG PROCESSING")
    print("--------------------------------")

    print("Total valid records:", len(logs))

    print("\nLogin status summary:")
    print(logs["status"].value_counts())

    print("\nProcessed dataset:")
    print(logs.head())

    print("\nLog processing completed successfully!")