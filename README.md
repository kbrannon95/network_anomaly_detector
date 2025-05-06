# Network Anomaly Detector

This tool uses an Isolation Forest model to detect anomalies in network traffic stored in PCAP files. It extracts features like packet length, protocol type, and inter-arrival time from each packet, then flags unusual behavior.

## How to Use

1. Place your `.pcap` files in a folder called `pcap_files`.

    There pcap_files directory is prepopulated with test files. Make sure to remove these before creating the model on your pcap data

2. Build the Docker image:

   docker build -t anomaly-detector .

3. Run the Docker container:

   docker run --rm -v ${PWD}/pcap_files:/data -v ${PWD}/output:/output anomaly-detector /data /output

   On Windows, use:

   docker run --rm -v ${PWD}\pcap_files:/data -v ${PWD}\output:/output anomaly-detector /data /output

4. After running, the results will be saved to `output/detection_results.csv`.

Each row in the CSV contains extracted features, an anomaly score, and a prediction (-1 = anomaly, 1 = normal). The script also reports the percentage of traffic identified as anomalous.
