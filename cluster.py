import email
import re
import hashlib
from email import policy
from email.parser import BytesParser
import os
import json # For saving the output

# Basic URL regex (can be improved)
URL_REGEX = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
import shutil
import os
import email
from email import policy
from email.message import EmailMessage
import extract_msg
import traceback # To print detailed errors

# Magic bytes for Microsoft Compound File Binary Format (used by .msg)
MSG_MAGIC_BYTES = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'

def check_email_format(filepath):
    """
    Checks if a file is a valid .eml, .msg, or neither.

    Args:
        filepath (str): The path to the file.

    Returns:
        str: 'eml', 'msg', or 'non-email'.
    """
    # 1. Basic check using extension (quick filter)
    ext = os.path.splitext(filepath)[1].lower()

    try:
        # 2. Check for .msg using magic bytes
        if filepath:
            with open(filepath, 'rb') as f:
                initial_bytes = f.read(len(MSG_MAGIC_BYTES))
                if initial_bytes == MSG_MAGIC_BYTES:
                    print(initial_bytes)
                    print("file type is msg-------------------------------------")
                    return 'msg'
                

        # 3. Check for .eml by trying to parse headers
        if filepath:
            try:
                # EML is text-based, try reading as text first
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    # Look for common headers in the first few lines
                    header_lines = [f.readline() for _ in range(10)]
                    header_content = "".join(header_lines)
                    # A very basic check - look for common patterns
                    if "From:" in header_content or "To:" in header_content or "Subject:" in header_content or "Date:" in header_content or "Received:" in header_content:
                         # More robust: try parsing
                         f.seek(0) # Go back to start
                         headers = email.parser.HeaderParser(policy=policy.default).parse(f)
                         if headers.items(): # Check if any headers were parsed
                             return 'eml'
            except Exception:
                 # If reading as text fails or parsing fails, might still be binary .eml? Less common.
                 # Try parsing as bytes for robustness (less common for typical .eml)
                 try:
                      with open(filepath, 'rb') as f:
                          headers = email.parser.BytesHeaderParser(policy=policy.default).parse(f)
                          if headers.items():
                              return 'eml'
                 except Exception:
                      pass # Fall through if byte parsing also fails
            # If extension is .eml but checks fail, treat as non-email
            return 'non-email'

        # 4. If extension isn't .msg or .eml, assume non-email
        return 'non-email'

    except FileNotFoundError:
        print(f"Error: File not found - {filepath}")
        return 'non-email'
    except PermissionError:
        print(f"Error: Permission denied - {filepath}")
        return 'non-email'
    except Exception as e:
        print(f"An unexpected error occurred while checking {filepath}: {e}")
        traceback.print_exc()
        return 'non-email'


def convert_msg_to_eml(filepath):
    """
    Converts a .msg file to .eml format and replaces the original file.
    Skips files that are not identified as .msg.

    Args:
        filepath (str): The path to the file.

    Returns:
        bool: True if conversion was successful, False otherwise.
    """
    file_format = check_email_format(filepath)

    if file_format != 'msg':
        # print(f"Skipping non-MSG file: {filepath} (detected as: {file_format})")
        return False

    print(f"Converting MSG file: {filepath}")
    eml_filepath = os.path.splitext(filepath)[0] + '.eml'

    try:
        # Use extract_msg to parse the .msg file
        msg_obj = extract_msg.Message(filepath)

        # Create an EmailMessage object (standard Python email library)
        eml_msg = EmailMessage()

        # --- Transfer Headers ---
        # Basic headers - map common ones. Note: extract_msg property names might differ.
        if msg_obj.sender:
            eml_msg['From'] = msg_obj.sender
        if msg_obj.to:
            eml_msg['To'] = msg_obj.to
        if msg_obj.cc:
            eml_msg['Cc'] = msg_obj.cc
        # BCC is usually not stored directly or accessible easily in saved .msg
        if msg_obj.subject:
            eml_msg['Subject'] = msg_obj.subject
        if msg_obj.date: # extract_msg provides date as string
            # Try parsing the date string or just use it as is
             try:
                 # Standard library parsing is preferred if format is known/standard
                 # from email.utils import parsedate_to_datetime
                 # dt = parsedate_to_datetime(msg_obj.date)
                 # eml_msg['Date'] = dt
                 # For simplicity, just assign the string if parsing is complex
                 eml_msg['Date'] = msg_obj.date
             except Exception:
                 eml_msg['Date'] = msg_obj.date # Fallback to raw string

        # Add a basic MIME-Version header
        eml_msg['MIME-Version'] = '1.0'

        # --- Transfer Body ---
        # Prioritize HTML body if available, otherwise use plain text body
        if msg_obj.htmlBody:
            html_body = msg_obj.htmlBody
        plain_body = msg_obj.body

        if html_body:
            # Need to decode if it's bytes
            try:
                # extract_msg often gives html_body as bytes, needs decoding
                # Guess encoding or use a common one like utf-8
                html_content = html_body.decode('utf-8', errors='replace')
                eml_msg.set_content(html_content, subtype='html', cte='quoted-printable')
                 # Add plain text alternative if available
                if plain_body:
                    eml_msg.add_alternative(plain_body, subtype='plain', cte='quoted-printable') # Add plain text version
            except AttributeError: # If it's already a string
                 eml_msg.set_content(html_body, subtype='html', cte='quoted-printable')
                 if plain_body:
                    eml_msg.add_alternative(plain_body, subtype='plain', cte='quoted-printable') # Add plain text version
            except Exception as e:
                 print(f"  Warning: Could not decode HTML body for {filepath}: {e}")
                 if plain_body:
                    eml_msg.set_content(plain_body, subtype='plain', cte='quoted-printable') # Fallback to plain text


        elif plain_body:
            eml_msg.set_content(plain_body, subtype='plain', cte='quoted-printable')
        else:
            eml_msg.set_content("", subtype='plain') # Ensure there's at least an empty body

        # --- Transfer Attachments ---
        if msg_obj.attachments:
            for attachment in msg_obj.attachments:
                try:
                    attachment_data = attachment.data
                    if attachment_data:
                         # Determine content type (can use mimetypes library for better guessing)
                         maintype, subtype = attachment.mimetype.split('/', 1) if attachment.mimetype and '/' in attachment.mimetype else ('application', 'octet-stream')
                         eml_msg.add_attachment(attachment_data,
                                               maintype=maintype,
                                               subtype=subtype,
                                               filename=attachment.long_filename or attachment.short_filename or 'attachment')
                except Exception as attach_error:
                     print(f"  Warning: Could not process attachment in {filepath}: {attach_error}")


        # --- Write the EML file ---
        with open(eml_filepath, 'wb') as f: # Write as bytes
            f.write(eml_msg.as_bytes())

        print(f"  Successfully converted to: {eml_filepath}")

        # --- Remove the original MSG file ---
        msg_obj.close()
        try:
            os.remove(filepath)
            print(f"  Removed original MSG file: {filepath}")
            return True
        except OSError as e:
            print(f"  Error removing original MSG file {filepath}: {e}")
            # Consider what to do if removal fails - maybe keep both?
            return False # Indicate partial success/failure

    except FileNotFoundError:
        print(f"Error: MSG file not found during conversion - {filepath}")
        return False
    except PermissionError:
        print(f"Error: Permission denied during conversion - {filepath}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during conversion of {filepath}: {e}")
        traceback.print_exc()
        # Clean up potentially created .eml file if conversion failed midway
        if os.path.exists(eml_filepath):
            try:
                os.remove(eml_filepath)
                print(f"  Cleaned up partially created EML file: {eml_filepath}")
            except OSError:
                print(f"  Warning: Could not clean up partial EML file: {eml_filepath}")
        return False

# --- Example Usage: Process all files in a directory ---
def process_directory(directory_path):
    """
    Processes all files in a directory, converting .msg to .eml.
    """
    if not os.path.isdir(directory_path):
        print(f"Error: Provided path is not a directory: {directory_path}")
        return

    print(f"\nProcessing directory: {directory_path}\n{'-'*30}")
    converted_count = 0
    skipped_count = 0
    error_count = 0

    for filename in os.listdir(directory_path):
        filepath = os.path.join(directory_path, filename)
        if os.path.isfile(filepath): # Ensure it's a file
            try:
                if convert_msg_to_eml(filepath):
                    converted_count += 1
                else:
                    # Check format again to categorize skip reason
                    fmt = check_email_format(filepath)
                    if fmt == 'eml' or fmt == 'non-email':
                         skipped_count +=1
                         # print(f"Skipped: {filename} (Format: {fmt})") # Optional: more verbose skipping
                    # If conversion failed, it's already counted implicitly by the return False

            except Exception as e:
                 print(f"Critical error processing file {filepath}: {e}")
                 traceback.print_exc()
                 error_count += 1
        # Optional: Add handling for subdirectories if needed using os.walk

    print(f"\n{'-'*30}\nProcessing Complete.")
    print(f"Successfully converted: {converted_count}")
    print(f"Skipped (non-MSG or already EML): {skipped_count}")
    print(f"Errors during processing: {error_count}")


def extract_features(eml_path):
    features = {
        'filepath': eml_path,
        'source_ip': None,
        'message_id': None,
        'subject': None,
        'from': None,
        'urls': set(), # Use a set to store unique URLs
        'body_hash': None # Simple hash for this example
    }
    try:
        with open(eml_path, 'rb') as fp:
            msg = BytesParser(policy=policy.default).parse(fp)

            # --- Header Features ---
            features['message_id'] = msg.get('Message-ID')
            features['subject'] = msg.get('Subject')
            features['from'] = msg.get('From')

            # Extract Source IP from the last 'Received' header
            received_headers = msg.get_all('Received')
            if received_headers:
                last_received = received_headers[0] # Headers are prepended
                ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', last_received)
                if ip_match:
                    features['source_ip'] = ip_match.group(1)
                # Fallback if IP is not in brackets (less reliable)
                elif not features['source_ip']:
                     ip_match = re.search(r'from\s+.*?\(.*?\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', last_received)
                     if ip_match:
                         features['source_ip'] = ip_match.group(1)


            # --- Body Features ---
            body_content = ""
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    cdispo = str(part.get('Content-Disposition'))
                    # Look for text/plain or text/html, ignore attachments
                    if ctype in ['text/plain', 'text/html'] and 'attachment' not in cdispo:
                        try:
                            payload = part.get_payload(decode=True)
                            charset = part.get_content_charset() or 'utf-8' # Guess charset if not specified
                            body_content += payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError, AttributeError) as e:
                            print(f"Error decoding part in {eml_path}: {e}") # Handle potential decoding issues
            else:
                 try:
                    payload = msg.get_payload(decode=True)
                    charset = msg.get_content_charset() or 'utf-8'
                    body_content = payload.decode(charset, errors='replace')
                 except (LookupError, UnicodeDecodeError, AttributeError) as e:
                    print(f"Error decoding body in {eml_path}: {e}")

            # Extract URLs from body
            found_urls = re.findall(URL_REGEX, body_content)
            features['urls'] = set(found_urls) # Store unique URLs

            # Simple body hash (use ssdeep for better fuzzy matching)
            if body_content:
                features['body_hash'] = hashlib.sha256(body_content.encode('utf-8', errors='replace')).hexdigest()

    except Exception as e:
        print(f"Error processing {eml_path}: {e}") # Catch other potential errors

    return features


def cluster_emails(directory):
    all_features = []
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename:
                filepath = os.path.join(root, filename)
                features = extract_features(filepath)
                if features: # Only add if features were extracted successfully
                    all_features.append(features)

    campaigns = {}
    campaign_id_counter = 0
    print(all_features)

    # Simple Clustering Rules (can be expanded)
    for i, email1 in enumerate(all_features):
        assigned_campaign = None
        # Check if already assigned
        for cid, data in campaigns.items():
            if email1['filepath'] in data['files']:
                assigned_campaign = cid
                break
        if assigned_campaign is not None:
            continue # Already part of a campaign

        # Try to find a match with subsequent emails
        potential_matches = []
        for j, email2 in enumerate(all_features):
            if i == j: continue # Don't compare with self

            # --- Define Match Criteria ---
            match_score = 0
            # Rule 1: Same Source IP (strong indicator)
            if email1['source_ip'] and email1['source_ip'] == email2['source_ip']:
                match_score += 3
            # Rule 2: Shared URL (especially non-common ones)
            if email1['urls'] and email2['urls']:
                 common_urls = email1['urls'].intersection(email2['urls'])
                 # Filter out very common domains if needed (e.g., google.com)
                 if common_urls:
                     match_score += 2 # Score higher if a less common URL is shared
            # Rule 3: Similar Body Hash (very strong indicator if exact match)
            if email1['body_hash'] and email1['body_hash'] == email2['body_hash']:
                 match_score += 5
            # Rule 4: Similar Subject (weaker indicator, check for patterns)
            if email1['subject'] and email1['subject'] == email2['subject']:
                 match_score += 1


            # --- Threshold for Campaign ---
            if match_score >= 5: # Adjust threshold based on desired strictness
                potential_matches.append(email2)

        # If matches found, create/add to campaign
        if potential_matches:
            campaign_id = f"Campaign_{campaign_id_counter}"
            campaigns[campaign_id] = {'files': [email1['filepath']], 'features': [email1]}
            for match in potential_matches:
                 # Check if the matched email isn't already assigned elsewhere
                 already_assigned = False
                 for cid, data in campaigns.items():
                    if match['filepath'] in data['files']:
                        already_assigned = True
                        break
                 if not already_assigned:
                    campaigns[campaign_id]['files'].append(match['filepath'])
                    campaigns[campaign_id]['features'].append(match) # Store features for review
            campaign_id_counter += 1
        # Optional: Handle emails that don't match any cluster (assign to 'Unclustered'?)


    # --- Output ---
    # Print summary or save to JSON/CSV
    print(f"Processed {len(all_features)} emails.")
    print(f"Identified {len(campaigns)} potential campaigns.")
    for cid, data in campaigns.items():
        print(f"- {cid}: {len(data['files'])} emails")
        
        # Optionally print dominant features like source IP or common URL

    # --- Save detailed results to JSON ---
    json_output_path = os.path.join(directory, 'campaign_clusters.json')
    try:
        with open(json_output_path, 'w') as f:
            # Convert sets to lists for JSON serialization
            serializable_campaigns = {}
            for cid, data in campaigns.items():
                serializable_features = []
                for feat in data['features']:
                     # Convert set to list within each feature dict
                     feat_copy = feat.copy()
                     if 'urls' in feat_copy:
                         feat_copy['urls'] = list(feat_copy['urls'])
                     serializable_features.append(feat_copy)
                serializable_campaigns[cid] = {'files': data['files'], 'features': serializable_features}

            json.dump(serializable_campaigns, f, indent=4)
        print(f"\nDetailed cluster information saved to: {json_output_path}")
    except Exception as e:
        print(f"\nError saving JSON output: {e}")


    print(f"\nCreating Campaign Folders and Copying Files...\n{'-'*30}")
    # --- Create Folders and Copy Files ---
    for cid, data in campaigns.items():
        campaign_folder_path = os.path.join(directory, cid)
        try:
            os.makedirs(campaign_folder_path, exist_ok=True)
            print(f"Created folder: {campaign_folder_path}")

            for original_eml_filepath in data['files']:
                try:
                    # Make sure the source file still exists before copying
                    if os.path.exists(original_eml_filepath):
                        filename = os.path.basename(original_eml_filepath)
                        destination_filepath = os.path.join(campaign_folder_path, filename)
                        shutil.copy2(original_eml_filepath, destination_filepath) # copy2 preserves metadata
                        # print(f"  Copied: {filename} to {cid}") # Can be very verbose
                    else:
                        print(f"  Warning: Source file not found, cannot copy: {original_eml_filepath}")
                except Exception as copy_error:
                    print(f"  Error copying file {original_eml_filepath} to {cid}: {copy_error}")
        except OSError as e:
            print(f"Error creating directory {campaign_folder_path}: {e}")
        except Exception as e:
             print(f"An unexpected error occurred while processing folder for {cid}: {e}")

# --- Run the clustering ---
email_directory = 'C:\\Users\\admin\\Desktop\\Project\\23500646739\\' # <--- Set your directory path here
#process_directory(email_directory)
cluster_emails(email_directory)
