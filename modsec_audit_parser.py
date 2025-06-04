import json
import re
import csv
from datetime import datetime
import pandas as pd

class ModSecurityLogParser:
    def __init__(self):
        self.patterns = {
            'timestamp': r'\[([^\]]+)\]',
            'transaction_id': r'\] (\d+\.\d+) \d+',
            'source_ip': r'\] \d+\.\d+ (\d+\.\d+\.\d+\.\d+) \d+',
            'source_port': r'\d+\.\d+\.\d+\.\d+ (\d+) \d+\.\d+\.\d+\.\d+',
            'server_ip': r'\d+ (\d+\.\d+\.\d+\.\d+) \d+$',
            'server_port': r'\d+\.\d+\.\d+\.\d+ (\d+)$',
            'rule_id': r'\[id "(\d+)"\]',
            'msg': r'\[msg "([^"]+)"\]',
            'uri': r'\[uri "([^"]+)"\]',
            'severity': r'\[severity "(\d+)"\]',
            'value': r"against variable '[^']+' \(Value: '([^']+)'",
            'ref': r'\[ref "([^"]+)"\]',
            'operator': r'Matched "Operator `([^\']+)\' with parameter',
            'variable': r"against variable '([^']+)'",
            'file': r'\[file "([^"]+)"\]',
            'line': r'\[line "(\d+)"\]'
        }
        
    def parse_audit_header(self, header):
        """Parse the audit header section"""
        result = {
            'timestamp': None,
            'transaction_id': None,
            'source_ip': None,
            'source_port': None,
            'server_ip': None,
            'server_port': None
        }
        
        # Extract timestamp
        timestamp_match = re.search(self.patterns['timestamp'], header)
        if timestamp_match:
            result['timestamp'] = timestamp_match.group(1)
        
        # Extract transaction ID
        trans_id_match = re.search(self.patterns['transaction_id'], header)
        if trans_id_match:
            result['transaction_id'] = trans_id_match.group(1)
        
        # Extract source IP and port
        source_ip_match = re.search(self.patterns['source_ip'], header)
        if source_ip_match:
            result['source_ip'] = source_ip_match.group(1)
        
        source_port_match = re.search(self.patterns['source_port'], header)
        if source_port_match:
            result['source_port'] = source_port_match.group(1)
        
        # Extract server IP and port
        server_ip_match = re.search(self.patterns['server_ip'], header)
        if server_ip_match:
            result['server_ip'] = server_ip_match.group(1)
        
        server_port_match = re.search(self.patterns['server_port'], header)
        if server_port_match:
            result['server_port'] = server_port_match.group(1)
        
        return result
    
    def parse_audit_messages(self, messages):
        """Parse the audit messages section"""
        # Split by ModSecurity entries
        entries = messages.split('\nModSecurity:')
        if len(entries) > 1:
            entries = ['ModSecurity:' + e for e in entries[1:]]
            entries = [messages.split('\nModSecurity:')[0]] + entries
        else:
            entries = [messages]
        
        parsed_entries = []
        
        for entry in entries:
            if not entry.strip():
                continue
                
            parsed = {
                'rule_id': None,
                'msg': None,
                'uri': None,
                'severity': None,
                'value': None,
                'ref': None,
                'operator': None,
                'variable': None
            }
            
            # Extract rule ID
            rule_id_match = re.search(self.patterns['rule_id'], entry)
            if rule_id_match:
                parsed['rule_id'] = rule_id_match.group(1)
            
            # Extract message
            msg_match = re.search(self.patterns['msg'], entry)
            if msg_match:
                parsed['msg'] = msg_match.group(1)
            
            # Extract URI
            uri_match = re.search(self.patterns['uri'], entry)
            if uri_match:
                parsed['uri'] = uri_match.group(1)
            
            # Extract severity
            severity_match = re.search(self.patterns['severity'], entry)
            if severity_match:
                parsed['severity'] = severity_match.group(1)
            
            # Extract value
            value_match = re.search(self.patterns['value'], entry)
            if value_match:
                parsed['value'] = value_match.group(1)
            
            # Extract ref
            ref_match = re.search(self.patterns['ref'], entry)
            if ref_match:
                parsed['ref'] = ref_match.group(1)
            
            # Extract operator
            operator_match = re.search(self.patterns['operator'], entry)
            if operator_match:
                parsed['operator'] = operator_match.group(1)
            
            # Extract variable
            variable_match = re.search(self.patterns['variable'], entry)
            if variable_match:
                parsed['variable'] = variable_match.group(1)
            
            parsed_entries.append(parsed)
        
        return parsed_entries
    
    def detect_targeted_fields(self, value):
        """Detect targeted fields from the value"""
        fields = []
        if value:
            value_lower = value.lower()
            if 'email' in value_lower:
                fields.append('email')
            if 'password' in value_lower:
                fields.append('password')
        return ','.join(fields) if fields else ''
    
    def process_log_entry(self, entry):
        """Process a single log entry"""
        event_id = entry.get('id', '')
        header = entry.get('sections', {}).get('A-audit_header', '')
        messages = entry.get('sections', {}).get('H-audit_messages', '')
        
        # Parse header
        header_data = self.parse_audit_header(header)
        
        # Initialize result with header data
        result = {
            'event_id': event_id,
            'transaction_id': header_data['transaction_id'],
            'timestamp': header_data['timestamp'],
            'source_ip': header_data['source_ip'],
            'source_port': header_data['source_port'],
            'target_endpoint': '',
            'rule_id': '',
            'reference': '',
            'sql_injection': False,
            'xss': False,
            'ssrf': False,
            'targeted_field': '',
            'layer_type': 'SINGLE_LAYERED',
            'sql_value': '',
            'ssrf_value': '',
            'xss_value': '',
            'sql_severity': '',
            'ssrf_severity': '',
            'xss_severity': ''
        }
        
        # Check if messages are empty
        if not messages.strip():
            return [result]
        
        # Parse messages
        parsed_messages = self.parse_audit_messages(messages)
        
        # Determine layer type
        if messages.count('\nModSecurity:') > 0:
            result['layer_type'] = 'MULTI_LAYERED'
        
        # Aggregate data from all messages
        rule_ids = []
        refs = []
        all_targeted_fields = set()
        
        for msg in parsed_messages:
            # Update endpoint
            if msg['uri'] and not result['target_endpoint']:
                result['target_endpoint'] = msg['uri']
            
            # Collect rule IDs
            if msg['rule_id']:
                rule_ids.append(msg['rule_id'])
            
            # Collect references
            if msg['ref']:
                refs.append(msg['ref'])
            
            # Detect attack types
            if msg['msg']:
                msg_lower = msg['msg'].lower()
                
                if 'sql injection' in msg_lower:
                    result['sql_injection'] = True
                    if msg['value']:
                        result['sql_value'] = msg['value']
                    if msg['severity']:
                        result['sql_severity'] = msg['severity']
                
                elif 'xss' in msg_lower:
                    result['xss'] = True
                    if msg['value']:
                        result['xss_value'] = msg['value']
                    if msg['severity']:
                        result['xss_severity'] = msg['severity']
                
                elif 'ssrf' in msg_lower:
                    result['ssrf'] = True
                    if msg['value']:
                        result['ssrf_value'] = msg['value']
                    if msg['severity']:
                        result['ssrf_severity'] = msg['severity']
            
            # Detect targeted fields
            if msg['value']:
                fields = self.detect_targeted_fields(msg['value'])
                if fields:
                    for field in fields.split(','):
                        all_targeted_fields.add(field)
        
        # Aggregate results
        result['rule_id'] = ','.join(rule_ids)
        result['reference'] = ','.join(refs)
        result['targeted_field'] = ','.join(sorted(all_targeted_fields))
        
        return [result]
    
    def process_json_file(self, input_file, output_file):
        """Process JSON file and output to CSV"""
        # Read JSON file
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        # Process all entries
        all_results = []
        for entry in data:
            results = self.process_log_entry(entry)
            all_results.extend(results)
        
        # Write to CSV
        fieldnames = [
            'event_id', 'transaction_id', 'timestamp', 'source_ip', 'source_port',
            'target_endpoint', 'rule_id', 'reference', 'sql_injection', 'xss', 'ssrf',
            'targeted_field', 'layer_type', 'sql_value', 'ssrf_value', 'xss_value',
            'sql_severity', 'ssrf_severity', 'xss_severity'
        ]
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_results)

if __name__ == "__main__":
    parser = ModSecurityLogParser()
    df = parser.process_json_file('modsec_audit_samples_combined.json', 'modsec_parsed_output.csv')