import os
import re
import time
import pandas as pd
import requests
from tqdm import tqdm

# ----------------------------------------------------------------------
# clean_snippet: Clean the raw PowerShell snippet
#
# Replaces newline and carriage return characters with a space,
# collapses multiple spaces into one, and trims leading/trailing spaces.
# Produces a one-line string for easier parsing.
# ----------------------------------------------------------------------
def clean_snippet(snippet):
    cleaned = snippet.replace("\r", " ").replace("\n", " ")
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned.strip()

# ----------------------------------------------------------------------
# extract_url: Extract the download URL from the snippet
#
# Searches for a pattern like: -Uri "https://..."
# If not found, falls back to any substring starting with http:// or https://.
# Returns the extracted URL or None if not found.
# ----------------------------------------------------------------------
def extract_url(snippet):
    pattern = r'-Uri\s+"([^"]+)"'
    match = re.search(pattern, snippet, re.IGNORECASE)
    if match:
        return match.group(1)
    url_pattern = r'(https?://[^\s"]+)'
    match = re.search(url_pattern, snippet)
    return match.group(1) if match else None

# ----------------------------------------------------------------------
# parse_powershell_snippet: Extract User-Agent and Cookies from the snippet
#
# Searches for:
#   - The User-Agent string from a line like: $session.UserAgent = "..."
#   - Cookies from lines such as:
#         $session.Cookies.Add((New-Object System.Net.Cookie("name", "value", "path", "domain")))
# Returns a dictionary with keys "UserAgent" and "cookies" (a dictionary of cookie name to value).
# ----------------------------------------------------------------------
def parse_powershell_snippet(snippet):
    config = {}
    ua_pattern = r'\$session\.UserAgent\s*=\s*"([^"]+)"'
    ua_match = re.search(ua_pattern, snippet, re.IGNORECASE)
    config["UserAgent"] = ua_match.group(1) if ua_match else None

    cookie_pattern = r'\$session\.Cookies\.Add\(\(New-Object System\.Net\.Cookie\("([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\)\)\)'
    cookies = {}
    for name, value, path, domain in re.findall(cookie_pattern, snippet, re.IGNORECASE):
        cookies[name] = value
    config["cookies"] = cookies
    return config

# ----------------------------------------------------------------------
# parse_additional_headers: Extract additional headers from the snippet
#
# Looks for the header block following "-Headers @{" and extracts key-value
# pairs in the format "key"="value". Returns a dictionary of these headers.
# ----------------------------------------------------------------------
def parse_additional_headers(snippet):
    pattern = r'-Headers\s+@\{\s*(.*?)\s*\}'
    match = re.search(pattern, snippet, re.IGNORECASE | re.DOTALL)
    headers = {}
    if match:
        header_block = match.group(1)
        header_lines = re.findall(r'"([^"]+)"\s*=\s*"([^"]+)"', header_block)
        for key, value in header_lines:
            headers[key] = value
    return headers

# ----------------------------------------------------------------------
# download_file: Download the file from the URL with retries
#
# Uses the provided requests session to send a GET request (with streaming enabled)
# to the given URL, writes the content to the specified filename in chunks, and
# displays a progress bar. If an error occurs (e.g. HTTP errors), it waits for
# a specified delay before retrying.
# ----------------------------------------------------------------------
def download_file(session, url, filename, chunk_size=8192, retry_delay=1, timeout=(10, 60)):
    while True:
        try:
            print(f"\nAttempting to download: {url}")
            response = session.get(url, stream=True, timeout=timeout)
            print(f"Response status code: {response.status_code}")
            response.raise_for_status()
            total_size = int(response.headers.get("content-length", 0))
            with open(filename, "wb") as f, tqdm(total=total_size, unit="B", unit_scale=True,
                                                  desc=f"Downloading {filename}") as progress:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        progress.update(len(chunk))
            print(f"Download complete. File saved as {filename}\n")
            break
        except Exception as e:
            print(f"Error encountered: {e}. Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)

# ----------------------------------------------------------------------
# main: Main function that processes the CSV and downloads files
#
# Steps:
# 1. Prompt the user for a base name. If the input can be converted to an integer,
#    it will use that as the starting number for the file names.
# 2. Read the CSV file (acclink.csv) which should contain a column named "snippet".
# 3. For each row, clean the snippet, extract the download URL, and parse configuration
#    (User-Agent, cookies) and additional headers. Debug information is printed.
# 4. Create a requests session using configuration from the first snippet.
# 5. For each extracted URL:
#    - Generate an output filename by incrementing the base name.
#    - Check if the file already exists; if so, skip downloading.
#    - Otherwise, download the file using the session.
# ----------------------------------------------------------------------
def main():
    base_input = input("Enter the base name for the AAC files (if a number, it will be incremented): ").strip()
    # Determine if the input is numeric (starting number) or a string base.
    try:
        start_num = int(base_input)
        is_numeric = True
    except ValueError:
        is_numeric = False

    try:
        df = pd.read_csv("acclink.csv")
    except Exception as e:
        print("Failed to read acclink.csv:", e)
        return

    if "snippet" not in df.columns:
        print("Error: The CSV file must contain a column named 'snippet'.")
        return

    extracted_urls = []
    configs = []
    add_headers_list = []
    print("\nProcessing snippets from acclink.csv:")
    for index, row in df.iterrows():
        raw_snippet = str(row["snippet"])
        cleaned = clean_snippet(raw_snippet)
        url = extract_url(cleaned)
        config = parse_powershell_snippet(cleaned)
        add_headers = parse_additional_headers(cleaned)
        extracted_urls.append(url)
        configs.append(config)
        add_headers_list.append(add_headers)
        print(f"\nRow {index+1} original snippet:")
        print(repr(raw_snippet))
        print(f"\nRow {index+1} cleaned snippet:")
        print(repr(cleaned))
        print(f"\nRow {index+1} extracted URL: {url}")
        print(f"Row {index+1} configuration:")
        print("  User-Agent:", config.get("UserAgent"))
        if config.get("cookies"):
            for cname, cvalue in config["cookies"].items():
                print(f"  Cookie {cname}: {cvalue}")
        else:
            print("  No cookies found.")
        print(f"Row {index+1} additional headers:")
        if add_headers:
            for hkey, hvalue in add_headers.items():
                print(f"  {hkey}: {hvalue}")
        else:
            print("  No additional headers found.")

    if not any(extracted_urls):
        print("No valid URLs were extracted. Exiting.")
        return

    # Create and configure the requests session using the first snippet's data.
    session = requests.Session()
    first_config = configs[0]
    if first_config.get("UserAgent"):
        session.headers.update({"User-Agent": first_config["UserAgent"]})
    else:
        session.headers.update({
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0")
        })
    session.cookies.update(first_config.get("cookies", {}))
    first_add_headers = add_headers_list[0]
    if first_add_headers:
        session.headers.update(first_add_headers)

    print("\nFinal Session Headers:")
    for key, value in session.headers.items():
        print(f"{key}: {value}")
    print("\nFinal Session Cookies:")
    for cookie in session.cookies:
        print(f"{cookie.name}: {cookie.value}")

    # Loop through each extracted URL and download the file if it doesn't exist.
    for idx, url in enumerate(extracted_urls):
        if not url:
            print(f"Row {idx+1}: No URL extracted. Skipping.")
            continue
        # Generate output filename:
        # If base name is numeric, increment the number; otherwise, append an underscore and the index+1.
        if is_numeric:
            output_filename = f"{start_num + idx}.aac"
        else:
            output_filename = f"{base_input}_{idx+1}.aac"
        if os.path.exists(output_filename):
            print(f"File '{output_filename}' already exists. Skipping download for row {idx+1}.")
            continue
        print(f"\nDownloading file {idx+1} from URL: {url}")
        download_file(session, url, output_filename)

if __name__ == "__main__":
    main()
