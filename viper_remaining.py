#!/usr/bin/python3
import os
import sys
import json
import datetime
import requests
from functools import reduce
from dotenv import load_dotenv
from pathlib import PureWindowsPath, PurePosixPath, Path

LOG_FILE = "/var/ossec/logs/viper.log"
OPEN_AI_MODEL = "gpt-4o-mini"
VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
OPEN_AI_KEY = os.getenv("OPEN_AI_KEY")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

OS_SUCCESS = 0
OS_INVALID = -1

# Write a log file for debugging.
def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(
            ar_name[ar_name.find("active-response"):])))
        log_file.write(str(datetime.datetime.now().strftime(
            "%a %b %d %H:%M:%S %Z %Y")) + " " + ar_name_posix + ": " + msg + "\n")


def VT_hash256(hash256):
    try:
        vt_url = f"https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            "apikey": VT_API_KEY,
            "resource": hash256
        }
        response = requests.get(vt_url, params=params)
        json_response = response.json()
    except Exception as e:
        write_debug_file("ERROR", f"VirusTotal Error: {e}")
        json_response = {"response_code": 0}  # Set a dummy response code

    return json_response


def OTX_hash256(hash256):
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/file/{
            hash256}"
        headers = {
            "X-OTX-API-KEY": f"{OTX_API_KEY}"
        }
        response = requests.get(otx_url, headers=headers)
        response.raise_for_status()  # Raise an exception for non-200 status codes

        json_response = response.json()

    except Exception as e:  # Handle other potential errors
        write_debug_file("ERROR", f"Unexpected Error: {e}")
        json_response = ""  # Set a dummy response code

    return json_response


def AI_Summary(message):
    try:
        gpt_url = f"https://api.openai.com/v1/chat/completions"
        header = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPEN_AI_KEY}"
        }
        data = {
            "model": f"{OPEN_AI_MODEL}",
            "messages": [
                {
                    "role": "system",
                    "content": "Analyze the following security alert and provide a concise, beginner-friendly summary that includes the most important details. Identify what the threat might be trying to do (e.g., ransomware, reverse shell, C2 server), assign a severity score from 0 to 10 based on the potential risk, and explain why the score was given. Highlight any notable compliance violations and mention if there are any VirusTotal or OTX (Open Threat Exchange) findings. Make you response Slack compatiable. Slack uses a single * around the text for bold letters."
                },
                {
                    "role": "user",
                    "content": message['text']
                }
            ]
        }
        response = requests.post(gpt_url, headers=header, json=data)
        write_debug_file("ERROR:", f"{response}")
    except Exception as e:
        response = ""
        write_debug_file("ERROR:", f"{e}")

    return response.json()

# Handle SHA256 FIM alerts by querying VirusTotal and notifying via Slack
def handle_sha256_fim(sha256_fim, alert_data):
    json_response = VT_hash256(sha256_fim)
    otx_response = OTX_hash256(sha256_fim)

    # Extract necessary fields from alert_data
    try:
        alert_time = alert_data["parameters"]["alert"]["timestamp"]
        file_path = alert_data["parameters"]["alert"]["full_log"].split(
            '\n')[0].replace('File "', '').replace('" added', '')
        event_type = alert_data["parameters"]["alert"]["syscheck"]["event"]
        agent = alert_data["parameters"]["alert"]["agent"]["name"]
        manager = alert_data["parameters"]["alert"]["manager"]["name"]
        rule_description = alert_data["parameters"]["alert"]["rule"]["description"]
        compliance = {
            "PCI DSS": alert_data["parameters"]["alert"]["rule"]["pci_dss"],
            "HIPAA": ", ".join(alert_data["parameters"]["alert"]["rule"]["hipaa"]),
            "TSC": ", ".join(alert_data["parameters"]["alert"]["rule"]["tsc"]),
            "NIST 800-53": alert_data["parameters"]["alert"]["rule"]["nist_800_53"],
            "GPG13": alert_data["parameters"]["alert"]["rule"]["gpg13"],
            "GDPR": alert_data["parameters"]["alert"]["rule"]["gdpr"]
        }
        file_details = {
            "Owner": alert_data["parameters"]["alert"]["syscheck"]["uname_after"],
            "Permissions": alert_data["parameters"]["alert"]["syscheck"]["perm_after"],
            "uid_after": alert_data["parameters"]["alert"]["syscheck"]["uid_after"],
            "gid_after": alert_data["parameters"]["alert"]["syscheck"]["gid_after"],
            "Size": alert_data["parameters"]["alert"]["syscheck"]["size_after"],
            "Inode": alert_data["parameters"]["alert"]["syscheck"]["inode_after"],
            "MD5": alert_data["parameters"]["alert"]["syscheck"]["md5_after"],
            "SHA1": alert_data["parameters"]["alert"]["syscheck"]["sha1_after"],
            "SHA256": sha256_fim
        }

    except KeyError as e:
        write_debug_file("ERROR", f"Missing key in alert data: {e}")

    # Prepare Slack message base
    base_message = {
        "text": f""" 
*Security Alert*

*{rule_description}*

*Additional Details*

*Alert Time:* {alert_time}

•  *Path:* {file_path}
•  *Event Type:* {event_type}
•  *Agent:* {agent} (IP: {alert_data["parameters"]["alert"]["agent"]["ip"]})
•  *Manager:* {manager}
•  *Compliance:* {', '.join([f'{k}: {v}' for k, v in compliance.items()])}
•  *File Details:*
    - *Permissions:* {file_details['Permissions']}
    - *Owner:* {file_details['Owner']} (UID: {file_details['uid_after']}, GID: {file_details['gid_after']})
    - *Size:* {file_details['Size']} bytes
    - *Inode:* {file_details['Inode']}
    - *Hashes:*
        - *MD5*: {file_details['MD5']}
        - *SHA1*: {file_details['SHA1']}
        - *SHA256*: {file_details['SHA256']}
"""
    }

    # Add VirusTotal details if found
    if json_response.get("response_code") == 1:
        vt_details = {
            "positives": json_response.get("positives", 0),
            "total": json_response.get("total", 0),
            "permalink": json_response.get("permalink", "")
        }
        base_message["text"] += f"""
•  *VirusTotal Details:*
        - *Positives:* {vt_details['positives']}
        - *Total:* {vt_details['total']}
        - *Detection URL:* {vt_details['permalink']}"""

    # Add OTX details if found
    if otx_response:
        pulse_info = otx_response.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        references = pulse_info.get("references", [])
        adversary = pulse_info.get("related", []).get(
            "alienvault", []).get("adversary", [])
        other_adversary = pulse_info.get("related", []).get(
            "other", []).get("adversary", [])

        base_message["text"] += f"""
•  *AlienVault OTX Details:*
        - *Adversary:* {adversary}
        - *Other Adversary:* {other_adversary}
        - *Pulse Count:* {pulse_count}
        - *References*: {references}"""

    # Get AI summary and insert it into the message
    ai_summary = AI_Summary({"text": base_message["text"]})
    # Assuming the content is under a 'content' key in the 'message' dictionary
    if isinstance(ai_summary, dict) and 'choices' in ai_summary and len(ai_summary['choices']) > 0:
        ai_summary_content = ai_summary['choices'][0]['message']['content']
    else:
        # Fallback in case the structure is different
        ai_summary_content = str(ai_summary)
        
    base_message["text"] = base_message["text"].replace(
        f"*{rule_description}*\n\n",
        f"*{rule_description}*\n\n{ai_summary_content}\n\n"
    )
    
    # Send the message
    headers = {'Content-type': 'application/json'}
    try:
        slack_response = requests.post(
            SLACK_WEBHOOK_URL, data=json.dumps(base_message), headers=headers)
        if slack_response.status_code != 200:
            write_debug_file("ERROR", f"Slack notification failed with status code {slack_response.status_code}: {slack_response.text}")
        else:
            write_debug_file("ERROR", "Slack notification sent successfully.")
    except Exception as e:
        write_debug_file("ERROR", f"Exception while sending Slack notification: {e}")

# Process alert to determine its type
def process_type(alert):
    def safe_get(data, *keys):
        try:
            return reduce(lambda d, key: d[key], keys, data)
        except (KeyError, TypeError):
            return None

    sha256_fim = safe_get(alert, "parameters", "alert", "syscheck", "sha256_after")

    if sha256_fim is not None:
        handle_sha256_fim(sha256_fim, alert)


# Get alert data from STDIN
def read_alert_data(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return OS_INVALID

    return data


def main(argv):
    write_debug_file(argv[0], "Started")
    alert = read_alert_data(argv)
    process_type(alert)
    write_debug_file(argv[0], "Ended")


if __name__ == "__main__":
    main(sys.argv)