# Email Campaign Clustering Tool

!(https://www.google.com/search?q=https://placehold.co/600x300/F0F8FF/4682B4%3Ftext%3DEmail%2BClustering%2BTool)

This Python tool analyzes a directory of email samples (.eml and .msg formats), converts .msg files to .eml, extracts key features, clusters emails into potential phishing/spam campaigns based on shared characteristics, and organizes the clustered emails into separate folders.

It's designed to help email security researchers and analysts quickly process large volumes of email samples to identify related threats.

Features

Format Detection: Identifies .eml, .msg, and non-email files.

MSG to EML Conversion: Converts Microsoft Outlook .msg files to the standard .eml format using the extract-msg library, replacing the original .msg file.

Feature Extraction: Parses .eml files to extract key metadata and content features:

Source IP Address (from the last Received header)

Message-ID

Subject

From address

Unique URLs found in the body

SHA256 hash of the body content

Campaign Clustering: Groups emails into potential campaigns based on configurable rules (currently based on shared Source IP, common URLs, identical body hash, and identical subject).

Folder Organization: Creates a sub-directory for each identified campaign (e.g., Campaign_001, Campaign_002) within the target directory.

File Copying: Copies the relevant .eml files into their corresponding campaign folders.

JSON Report: Outputs a campaign_clusters.json file in the target directory detailing the files and features associated with each identified campaign.

Requirements

Python 3.x

extract-msg library

Installation

Clone the repository:

git clone [your-repository-url]
cd [your-repository-directory]


Install dependencies:

pip install extract-msg pandas ssdeep # Optional pandas and ssdeep


(Note: pandas and ssdeep are optional but recommended for more advanced analysis/hashing if you extend the script).

Usage

Configure the Target Directory:

Open the email_processor.py script in a text editor.

Locate the TARGET_DIRECTORY variable near the end of the script.

Change the path /path/to/your/email/samples to the actual path of the directory containing your .eml and .msg files.

#--- Set the directory containing your email samples ---
TARGET_DIRECTORY = '/path/to/your/email/samples' # <--- !!! CHANGE THIS PATH !!!


Run the script:

python email_processor.py


Input

The script expects a single directory containing email sample files. It will process files with .eml and .msg extensions within that directory (it does not currently process subdirectories recursively, but could be modified to do so).

Output

After running, the TARGET_DIRECTORY will contain:

Converted .eml files: All original .msg files will be replaced by their .eml counterparts.

Campaign Folders: Sub-directories named Campaign_001, Campaign_002, etc., corresponding to the identified clusters (defaulting to clusters of 2 or more emails).

Clustered .eml files: Each campaign folder will contain copies of the .eml files belonging to that cluster.

JSON Report (campaign_clusters.json): A file detailing which emails belong to which campaign and the features extracted from them.

Clustering Logic

The current clustering logic uses a simple scoring system:

Shared Source IP: +3 points

Shared URL(s): +2 points

Identical Body Hash: +5 points

Identical Subject: +1 point

Emails are grouped into the same campaign if their pairwise comparison score meets or exceeds a threshold (currently set to 5). This threshold can be adjusted in the cluster_emails function for stricter or looser clustering.

Caveats & Future Improvements

Error Handling: While basic error handling is included, malformed email files can still cause issues. The script prints warnings for files it cannot process.

MSG Conversion Fidelity: The .msg to .eml conversion aims to preserve key headers, body, and attachments, but complex formatting or obscure Outlook-specific features might not be perfectly translated.

Feature Extraction Robustness: The IP address and URL extraction relies on regular expressions and might miss edge cases or heavily obfuscated data. Parsing Received headers accurately can be complex.

Clustering Simplicity: The current clustering is basic. More advanced methods (e.g., using fuzzy hashes like ssdeep for body comparison, graph-based clustering, or machine learning) could provide more nuanced results.

No Recursive Directory Scan: The script currently only processes the top-level directory specified.

License

[Specify your license here, e.g., MIT License, Apache 2.0, or leave blank if unsure]
