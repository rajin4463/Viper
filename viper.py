#!/usr/bin/python3
import sys
import json
import datetime
import requests
from functools import reduce
from pathlib import PureWindowsPath, PurePosixPath, Path
from notification_service import NotificationService
from message_builder import SecurityMessageBuilder

LOG_FILE = "/var/ossec/logs/viper.log"
VT_API_KEY = "427b9da09a5b11515b40d5963eadbe326bc347b7704ffa7170373e15bd1a510d"
OTX_API_KEY = "<YOUR_OTX_API_KEY>"
OPEN_AI_KEY = "<YOUR_OPENAI_API_KEY>"
OPEN_AI_MODEL = "gpt-4o-mini" # You can change this to any other model you have access to
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"

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


def AI_Summary(message, alert_data):
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
                    "content": "Analyze the following security alert and provide a concise, beginner-friendly summary that includes the most important details. Identify what the threat might be trying to do (e.g., ransomware, reverse shell, C2 server), assign a severity score from 0 to 10 based on the potential risk, and explain why the score was given. Highlight any notable Indicators of compermise (IOC),compliance violations and mention if there are any VirusTotal or OTX (Open Threat Exchange) findings. Make you response Slack compatiable. Slack uses a single * around the text for bold letters."
                },
                {
                    "role": "user",
                    "content": f"here is the raw security alert \n```\n{alert_data}\n````\n and here are some extracted and additional data from extenal sources \n```\n{message['text']}\n```\n"
                }
            ]
        }
        response = requests.post(gpt_url, headers=header, json=data)
        write_debug_file("ERROR:", f"{response}")
    except Exception as e:
        response = ""
        write_debug_file("ERROR:", f"{e}")

    return response.json()

# Initialize notification service
notification_service = NotificationService(SLACK_WEBHOOK_URL)

# Handle URL alerts by querying VirusTotal
def handle_url(url, alert_data):
    try:
        vt_url = f"https://www.virustotal.com/vtapi/v2/url/report"
        params = {
            "apikey": VT_API_KEY,
            "resource": url
        }
        response = requests.get(vt_url, params=params)
        json_response = response.json()

        if (json_response.get("response_code") == 0):
            write_debug_file("ERROR", f"URL: {url} not found on VirusTotal.")
            return

        for engine, result in json_response.get("scans", {}).items():
            if (result.get("detected")):
                write_debug_file("ERROR", f"Engine: {engine} detected this URL as malicious.")

        # Prepare and send Slack notification
        message = {
            "text": f"URL: {url} detected as malicious by VirusTotal."
        }
        success, error = notification_service.send_notification(message)
        if (not success):
            write_debug_file("ERROR", f"Failed to send notification: {error}")

    except Exception as e:
        write_debug_file("ERROR", f"Exception in handle_url: {e}")

# Handle SHA256 FIM alerts by querying VirusTotal and notifying via Slack
def handle_sha256_fim(sha256_fim, alert_data):
    json_response = VT_hash256(sha256_fim)
    otx_response = OTX_hash256(sha256_fim)

    try:
        alert = alert_data["parameters"]["alert"]
        message_builder = SecurityMessageBuilder()
        
        # Build the message using builder pattern
        message = (message_builder
            .add_header(alert["rule"]["description"])
            .add_basic_details(
                alert_time=alert["timestamp"],
                file_path=alert["full_log"].split('\n')[0].replace('File "', '').replace('" added', ''),
                event_type=alert["syscheck"]["event"],
                agent=alert["agent"]["name"],
                agent_ip=alert["agent"]["ip"],
                manager=alert["manager"]["name"]
            )
            .add_compliance({
                "PCI DSS": alert["rule"]["pci_dss"],
                "HIPAA": ", ".join(alert["rule"]["hipaa"]),
                "TSC": ", ".join(alert["rule"]["tsc"]),
                "NIST 800-53": alert["rule"]["nist_800_53"],
                "GPG13": alert["rule"]["gpg13"],
                "GDPR": alert["rule"]["gdpr"]
            })
            .add_file_details({
                "Owner": alert["syscheck"]["uname_after"],
                "Permissions": alert["syscheck"]["perm_after"],
                "uid_after": alert["syscheck"]["uid_after"],
                "gid_after": alert["syscheck"]["gid_after"],
                "Size": alert["syscheck"]["size_after"],
                "Inode": alert["syscheck"]["inode_after"],
                "MD5": alert["syscheck"]["md5_after"],
                "SHA1": alert["syscheck"]["sha1_after"],
                "SHA256": sha256_fim
            }))

        # Add VirusTotal details if found
        if (json_response.get("response_code") == 1):
            message.add_virustotal_results({
                "positives": json_response.get("positives", 0),
                "total": json_response.get("total", 0),
                "permalink": json_response.get("permalink", "")
            })

        # Add OTX details if found
        if (otx_response):
            message.add_otx_results(otx_response)

        # Get AI summary
        ai_summary = AI_Summary({"text": message.build()["text"]}, alert_data)
        if (isinstance(ai_summary, dict) and 'choices' in ai_summary and len(ai_summary['choices']) > 0):
            ai_summary_content = ai_summary['choices'][0]['message']['content']
            message.add_ai_summary(ai_summary_content)

        # Send the final message
        notification_service.queue_notification(message.build())
        notification_service.process_queue()

    except Exception as e:
        write_debug_file("ERROR", f"Exception in handle_sha256_fim: {e}")

# Process alert to determine its type

def process_type(alert):
    def safe_get(data, *keys):
        try:
            return reduce(lambda d, key: d[key], keys, data)
        except (KeyError, TypeError):
            return None

    url = safe_get(alert, "parameters", "alert", "data", "url")
    ip_address = safe_get(alert, "parameters", "alert", "data", "srcip")
    sha256_fim = safe_get(alert, "parameters", "alert",
                          "syscheck", "sha256_after")

    if (url is not None):
        handle_url(url, alert)
    if (sha256_fim is not None):
        handle_sha256_fim(sha256_fim, alert)


# Get alert data from STDIN
def read_alert_data(argv):
    # get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(
            argv[0], 'Decoding JSON has failed, invalid input format')
        return OS_INVALID

    return data


def main(argv):
    write_debug_file(argv[0], "Started")
    alert = read_alert_data(argv)
    process_type(alert)
    write_debug_file(argv[0], "Ended")


if __name__ == "__main__":
    main(sys.argv)
