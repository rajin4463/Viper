from typing import Dict, Any, Optional
from collections import defaultdict
import datetime

class SecurityMessageBuilder:
    def __init__(self, log_file):
        self.sections = defaultdict(str)
        self.section_order = [
            'header',
            'ai_summary',
            'basic_details',
            'compliance',
            'file_details',
            'virustotal',
            'otx'
        ]
        self.log_file = log_file

    def _write_log(self, msg):
        """Write to log file in the same format as viper"""
        with open(self.log_file, mode="a") as log_file:
            timestamp = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
            log_file.write(f"{timestamp} MessageBuilder: {msg}\n")

    def _add_if_exists(self, value: Any) -> bool:
        """Check if value exists and is not empty"""
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, dict)):
            return bool(value)
        return value is not None

    def add_header(self, rule_description: Optional[str]) -> 'SecurityMessageBuilder':
        if self._add_if_exists(rule_description):
            self._write_log(f"Adding header with rule: {rule_description[:50]}...")
            self.sections['header'] = (
                "*Security Alert*\n\n"
                f"*{rule_description}*\n"
            )
        return self

    def add_basic_details(self, **kwargs) -> 'SecurityMessageBuilder':
        self._write_log("Adding basic details to message")
        # Only add fields that have valid values
        details = []
        if self._add_if_exists(kwargs.get('alert_time')):
            details.append(f"*Alert Time:* {kwargs['alert_time']}\n")
        if self._add_if_exists(kwargs.get('file_path')):
            details.append(f"•  *Path:* {kwargs['file_path']}")
        if self._add_if_exists(kwargs.get('event_type')):
            details.append(f"•  *Event Type:* {kwargs['event_type']}")
        if self._add_if_exists(kwargs.get('agent')):
            agent_str = f"•  *Agent:* {kwargs['agent']}"
            if self._add_if_exists(kwargs.get('agent_ip')):
                agent_str += f" (IP: {kwargs['agent_ip']})"
            details.append(agent_str)
        if self._add_if_exists(kwargs.get('manager')):
            details.append(f"•  *Manager:* {kwargs['manager']}")

        if details:
            self.sections['basic_details'] = "\n*Additional Details*\n\n" + "\n".join(details) + "\n"
        return self

    def add_compliance(self, compliance: Dict[str, Any]) -> 'SecurityMessageBuilder':
        self._write_log("Adding compliance information")
        # Filter out empty compliance values
        valid_compliance = {k: v for k, v in compliance.items() if self._add_if_exists(v)}
        if valid_compliance:
            formatted_compliance = ', '.join([f'{k}: {v}' for k, v in valid_compliance.items()])
            self.sections['compliance'] = f"•  *Compliance:* {formatted_compliance}\n"
        return self

    def add_file_details(self, details: Dict[str, Any]) -> 'SecurityMessageBuilder':
        self._write_log("Adding file details")
        # Only add file details if we have valid information
        valid_details = {}
        for key, value in details.items():
            if self._add_if_exists(value):
                valid_details[key] = value

        if valid_details:
            file_details = ["•  *File Details:*"]
            if 'Permissions' in valid_details:
                file_details.append(f"    - *Permissions:* {valid_details['Permissions']}")
            if 'Owner' in valid_details:
                owner_str = f"    - *Owner:* {valid_details['Owner']}"
                if 'uid_after' in valid_details and 'gid_after' in valid_details:
                    owner_str += f" (UID: {valid_details['uid_after']}, GID: {valid_details['gid_after']})"
                file_details.append(owner_str)
            if 'Size' in valid_details:
                file_details.append(f"    - *Size:* {valid_details['Size']} bytes")
            if 'Inode' in valid_details:
                file_details.append(f"    - *Inode:* {valid_details['Inode']}")
            
            # Add hashes if they exist
            hashes = []
            for hash_type in ['MD5', 'SHA1', 'SHA256']:
                if hash_type in valid_details:
                    hashes.append(f"        - *{hash_type}*: {valid_details[hash_type]}")
            if hashes:
                file_details.append("    - *Hashes:*")
                file_details.extend(hashes)

            self.sections['file_details'] = "\n".join(file_details) + "\n"
        return self

    def add_virustotal_results(self, vt_details: Optional[Dict[str, Any]]) -> 'SecurityMessageBuilder':
        self._write_log("Adding VirusTotal results")
        if vt_details and any(self._add_if_exists(v) for v in vt_details.values()):
            details = ["•  *VirusTotal Details:*"]
            if self._add_if_exists(vt_details.get('positives')):
                details.append(f"        - *Positives:* {vt_details['positives']}")
            if self._add_if_exists(vt_details.get('total')):
                details.append(f"        - *Total:* {vt_details['total']}")
            if self._add_if_exists(vt_details.get('permalink')):
                details.append(f"        - *Detection URL:* {vt_details['permalink']}")
            self.sections['virustotal'] = "\n".join(details) + "\n"
        return self

    def add_otx_results(self, otx_response: Optional[Dict[str, Any]]) -> 'SecurityMessageBuilder':
        self._write_log("Adding OTX results")
        if not otx_response:
            return self

        pulse_info = otx_response.get("pulse_info", {})
        if not pulse_info:
            return self

        details = ["•  *AlienVault OTX Details:*"]
        if self._add_if_exists(pulse_info.get("related", {}).get("alienvault", {}).get("adversary")):
            details.append(f"        - *Adversary:* {pulse_info['related']['alienvault']['adversary']}")
        if self._add_if_exists(pulse_info.get("related", {}).get("other", {}).get("adversary")):
            details.append(f"        - *Other Adversary:* {pulse_info['related']['other']['adversary']}")
        if self._add_if_exists(pulse_info.get("count")):
            details.append(f"        - *Pulse Count:* {pulse_info['count']}")
        if self._add_if_exists(pulse_info.get("references")):
            details.append(f"        - *References*: {pulse_info['references']}")

        if len(details) > 1:  # Only add if we have more than just the header
            self.sections['otx'] = "\n".join(details) + "\n"
        return self

    def add_ai_summary(self, ai_content: Optional[str]) -> 'SecurityMessageBuilder':
        if self._add_if_exists(ai_content):
            self._write_log("Adding AI summary")
            self.sections['ai_summary'] = f"\n{ai_content}\n\n"
        return self

    def build(self) -> Dict[str, str]:
        self._write_log("Building final message")
        # Combine sections in the specified order, only including non-empty sections
        message = ""
        for section in self.section_order:
            if section in self.sections and self.sections[section]:
                message += self.sections[section]
        
        return {"text": message.strip()}
