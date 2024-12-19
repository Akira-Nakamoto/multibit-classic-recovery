import base64
import json
import numpy as np
from tqdm import tqdm

# Load configuration from config.json
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

keyfile_paths = config['keyfile_paths']

# Function to calculate entropy of a data chunk
def calculate_entropy(data):
    if len(data) == 0:
        return 0
    probabilities = np.bincount(data) / len(data)
    probabilities = probabilities[probabilities > 0]
    return -np.sum(probabilities * np.log2(probabilities))

# Function to process a file and calculate entropy for chunks
def process_file(filepath, chunk_size=16):
    try:
        with open(filepath, 'rb') as f:
            file_data = f.read()
        
        # Split file into chunks and calculate entropy for each
        results = []
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i + chunk_size]
            entropy = calculate_entropy(np.frombuffer(chunk, dtype=np.uint8))
            results.append((i, i + chunk_size, entropy))
        
        # Save results to an output file
        output_file = f"{filepath}.entropy.txt"
        with open(output_file, "w") as f:
            for start, end, entropy in results:
                f.write(f"- {start}–{end} bytes: Entropy = {entropy:.3f}\n")
        
        # Print results to the console
        print(f"Entropy results for {filepath}:")
        for start, end, entropy in results:
            print(f"     - {start}–{end} bytes: Entropy = {entropy:.3f}")
    
    except Exception as e:
        print(f"Error processing file {filepath}: {e}")

# Main function to process all files in the config
if __name__ == "__main__":
    for keyfile_path in tqdm(keyfile_paths, desc="Processing files"):
        process_file(keyfile_path)
