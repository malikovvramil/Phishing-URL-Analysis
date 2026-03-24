# Phishing-URL-Analysis

## Project Overview
This project presents a comprehensive system for collecting, processing, and analyzing malicious URLs sourced from various open-source threat intelligence feeds. It features an interactive Streamlit-based dashboard designed to visualize key findings related to phishing URLs, encompassing their distribution, associated threat families, daily arrival rates, patterns of Top-Level Domain (TLD) abuse, and distinct structural characteristics.

## Key Features & Benefits

*   **Automated Data Collection**: Efficiently fetches real-time malicious URL data from prominent open threat intelligence feeds, including URLhaus (abuse.ch) and OpenPhish.
*   **Robust Data Preprocessing**: Cleans, normalizes, and enriches raw URL data by extracting essential structural features such as scheme, registered domain, TLD, subdomain depth, path depth, URL length, query parameter presence, and identification of IP-based hosting.
*   **Interactive Analysis Dashboard (Streamlit)**: Provides a dynamic and user-friendly interface for in-depth analysis:
    *   **Live Filtering**: Filter data by source and URL scheme to refine analytical scope across all charts.
    *   **Key Performance Indicators (KPIs)**: A dedicated strip showcasing 5 headline numbers for quick insights into critical metrics.
    *   **URL Takedown Status**: Visualizes the distribution of URL takedown statuses from sources like URLhaus.
    *   **Threat / Malware-Family Spread**: Illustrates the prevalence and distribution of different threat types and malware families.
    *   **Daily Arrival Rates**: Tracks and displays the rate of new malicious URLs detected over time.
    *   **TLD Abuse & Top Domains**: Identifies commonly abused Top-Level Domains and top offending domains.
    *   **Cross-Feed Domain Overlap**: Analyzes domain overlap across different threat intelligence feeds using Venn breakdowns.
    *   **URL Structural Fingerprints**: Explores unique structural characteristics of phishing URLs to aid in detection and understanding.
*   **Modular Architecture**: Designed with separated concerns across `collector.py`, `processor.py`, and `analyzer.py` for enhanced maintainability, testability, and scalability.
*   **Debugging Utility**: Includes a `debug.py` script to easily inspect the raw output and connectivity status of external threat intelligence feeds, aiding in troubleshooting.

## Technologies

### Languages

*   Python

### Frameworks & Libraries

*   **Streamlit**: For building the interactive web dashboard.
*   **Pandas**: For powerful data manipulation and analysis.
*   **Requests**: For making HTTP requests to fetch data from external APIs.
*   **tldextract**: For accurately extracting TLD, domain, and subdomain from URLs.

## Project Structure

```
├── analyzer.py       # Contains pure analysis functions to generate findings for the dashboard.
├── app.py            # The main Streamlit application, defining the dashboard layout and interactivity.
├── collector.py      # Manages fetching raw malicious URL data from external threat intelligence feeds.
├── debug.py          # A utility script to test the connectivity and output of external data sources.
├── processor.py      # Responsible for cleaning, normalizing, and extracting structural features from raw URL data.
├── readme.txt        # (Placeholder for additional text, will be superseded by this README.md)
├── requirements.txt  # Lists all Python package dependencies required to run the project.
```

## Prerequisites

Before setting up the project, ensure you have the following installed:

*   **Python 3.8+**: The project is developed and tested with recent Python versions.
*   **pip**: Python's package installer, usually included with Python installations.

## Installation & Setup Instructions

Follow these steps to get the Phishing-URL-Analysis project running on your local machine:

1.  **Clone the Repository**

    First, clone the project repository to your local machine:

    ```bash
    git clone https://github.com/malikovvramil/Phishing-URL-Analysis.git
    cd Phishing-URL-Analysis
    ```

2.  **Create a Virtual Environment (Recommended)**

    It's highly recommended to use a virtual environment to manage project dependencies and avoid conflicts with other Python projects:

    ```bash
    python -m venv venv
    ```

    Activate the virtual environment:

    *   **On Windows**:
        ```bash
        venv\Scripts\activate
        ```
    *   **On macOS/Linux**:
        ```bash
        source venv/bin/activate
        ```

3.  **Install Dependencies**

    With your virtual environment activated, install all necessary Python libraries listed in `requirements.txt`:

    ```bash
    pip install -r requirements.txt
    ```

## Usage Examples

### Running the Phishing URL Analysis Dashboard

To launch the interactive dashboard, ensure your virtual environment is active and run the `app.py` script using Streamlit:

```bash
streamlit run app.py
```

This command will typically open the dashboard in your default web browser at `http://localhost:8501`.

**Dashboard Interaction:**
*   **Sidebar Filters**: Use the sidebar to apply filters based on data source (e.g., URLhaus, OpenPhish) and URL scheme (`http`, `https`). These filters dynamically update all charts on the dashboard.
*   **KPI Strip**: Observe the key metrics at the top for a quick summary.
*   **Analysis Sections**: Explore the various charts and graphs detailing URL takedown status, threat distribution, daily trends, and structural insights.

### Debugging Threat Intelligence Feeds

If you need to verify the connectivity to external threat intelligence feeds or inspect their raw output, you can use the `debug.py` script:

```bash
python debug.py
```

This script will make direct requests to the configured feed URLs (URLhaus CSV, OpenPhish TXT) and print their HTTP status codes and a snippet of the returned content. This is invaluable for troubleshooting data collection issues.

## Configuration Options

Currently, the URLs for the external threat intelligence feeds are hardcoded within `collector.py`. If you need to modify these endpoints or integrate new feeds, you will need to directly edit the `collector.py` file.

*   `collector.py`:
    *   `URLHAUS_CSV`: Defines the URL for the URLhaus recent CSV download.
    *   `OPENPHISH_TXT`: Defines the URL for the OpenPhish community feed (plain text).

For future enhancements, these could be moved to environment variables or a separate configuration file for easier management.

## Contributing Guidelines

We welcome contributions to the Phishing-URL-Analysis project! If you're interested in helping improve this tool, please follow these guidelines:

1.  **Fork the Repository**: Start by forking the `Phishing-URL-Analysis` repository to your GitHub account.
2.  **Create a New Branch**: Create a descriptive branch for your feature or bug fix:
    ```bash
    git checkout -b feature/your-feature-name
    # or for a bug fix
    git checkout -b bugfix/issue-description
    ```
3.  **Make Your Changes**: Implement your desired changes, ensuring your code is clean, well-commented, and adheres to the existing coding style.
4.  **Test Your Changes**: Although a dedicated test suite isn't fully established, please ensure your changes integrate correctly and do not introduce regressions. `analyzer.py` is designed for easy unit testing, so consider adding tests for new analysis functions.
5.  **Commit Your Changes**: Write clear and concise commit messages that explain the purpose of your changes.
    ```bash
    git commit -m "feat: Add new analysis for query parameter usage"
    ```
6.  **Push Your Branch**: Push your local branch to your forked repository on GitHub.
    ```bash
    git push origin feature/your-feature-name
    ```
7.  **Open a Pull Request**: Create a Pull Request from your branch to the `main` branch of the original repository. Please provide a detailed description of your changes and their benefits.

## License Information

This project currently **does not have an explicit license specified**.

It is highly recommended that a license be added to clarify the terms under which others can use, modify, and distribute this software. Common open-source licenses include MIT, Apache 2.0, or GPLv3.

## Acknowledgments

This project relies on the invaluable data and services provided by the following open-source threat intelligence feeds:

*   **URLhaus (abuse.ch)**: For their comprehensive and publicly available database of malicious URLs.
*   **OpenPhish**: For offering their community feed of confirmed phishing URLs.
