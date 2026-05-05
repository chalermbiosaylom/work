#!/usr/bin/env python3
"""
🛡️ AI Hallucination Guard
Prevents AI from reporting fake flags or making unfounded claims

Usage:
    from hallucination_guard import HallucinationGuard, EvidenceCollector
    
    guard = HallucinationGuard()
    is_valid, reason = guard.validate_flag_claim(flag, evidence)

Integrates with: ctf-ics skill for Windsurf IDE
"""

import re
import hashlib
import time
from typing import Dict, List, Tuple, Optional, Any


class HallucinationGuard:
    """
    Prevents AI hallucination in CTF solving
    Validates all claims against evidence
    """
    
    # Patterns that indicate hallucination
    HALLUCINATION_PATTERNS = [
        r'flag\{example\}',
        r'FLAG\{test\}',
        r'coc2026\{placeholder\}',
        r'coc2026\{sample\}',
        r'flag\{.*test.*\}',
        r'Unit ID 999',
        r'address 99999',
        r'port 99999',
    ]
    
    # Phrases that indicate speculation (not evidence)
    SPECULATION_PHRASES = [
        'the flag is',
        'flag should be',
        'flag might be',
        'probably the flag',
        'likely the flag',
        'could be the flag',
        'appears to be',
        'seems like',
    ]
    
    # Valid flag formats
    VALID_FLAG_FORMATS = [
        r'^coc2026\{[a-zA-Z0-9_!@#$%^&*()\-+=]+\}$',
        r'^FLAG\{[a-zA-Z0-9_!@#$%^&*()\-+=]+\}$',
        r'^CTF\{[a-zA-Z0-9_!@#$%^&*()\-+=]+\}$',
        r'^flag\{[a-zA-Z0-9_!@#$%^&*()\-+=]+\}$',
        r'^rtaf\{[a-zA-Z0-9_!@#$%^&*()\-+=]+\}$',
    ]
    
    def __init__(self):
        self.validation_log = []
    
    def validate_flag_claim(self, claimed_flag: str, evidence: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate that a claimed flag has proper evidence
        
        Args:
            claimed_flag: The flag being claimed
            evidence: Dict with 'command', 'output', 'timestamp'
        
        Returns:
            (is_valid, reason)
        """
        
        # Rule 1: Must have command evidence
        if 'command' not in evidence or not evidence['command']:
            self._log_validation(claimed_flag, False, "No command evidence")
            return (False, "HALLUCINATION: No command evidence provided")
        
        # Rule 2: Must have output evidence
        if 'output' not in evidence or not evidence['output']:
            self._log_validation(claimed_flag, False, "No output evidence")
            return (False, "HALLUCINATION: No output evidence provided")
        
        # Rule 3: Flag must appear in output
        if claimed_flag not in str(evidence['output']):
            self._log_validation(claimed_flag, False, "Flag not in output")
            return (False, "HALLUCINATION: Flag not found in command output")
        
        # Rule 4: Check for hallucination patterns
        for pattern in self.HALLUCINATION_PATTERNS:
            if re.search(pattern, claimed_flag, re.IGNORECASE):
                self._log_validation(claimed_flag, False, f"Hallucination pattern: {pattern}")
                return (False, f"HALLUCINATION: Pattern detected - {pattern}")
        
        # Rule 5: Validate flag format
        format_valid = False
        for pattern in self.VALID_FLAG_FORMATS:
            if re.match(pattern, claimed_flag):
                format_valid = True
                break
        
        if not format_valid:
            self._log_validation(claimed_flag, False, "Invalid format")
            return (False, "HALLUCINATION: Invalid flag format")
        
        # Rule 6: Check flag length (typical: 15-80 chars)
        if len(claimed_flag) < 10 or len(claimed_flag) > 100:
            self._log_validation(claimed_flag, False, "Suspicious length")
            return (False, f"HALLUCINATION: Suspicious flag length ({len(claimed_flag)} chars)")
        
        # Rule 7: Check for balanced braces
        if claimed_flag.count('{') != 1 or claimed_flag.count('}') != 1:
            self._log_validation(claimed_flag, False, "Unbalanced braces")
            return (False, "HALLUCINATION: Unbalanced braces in flag")
        
        # All checks passed
        self._log_validation(claimed_flag, True, "Validated")
        return (True, "Flag validated with evidence")
    
    def validate_unit_id_claim(self, unit_id: int, probe_result: Optional[Dict]) -> Tuple[bool, str]:
        """
        Validate Unit ID was actually probed
        """
        if probe_result is None:
            return (False, "HALLUCINATION: Unit ID not probed")
        
        active_units = probe_result.get('active_units', [])
        if unit_id not in active_units:
            return (False, f"HALLUCINATION: Unit ID {unit_id} not in active list {active_units}")
        
        return (True, f"Unit ID {unit_id} validated")
    
    def validate_address_claim(self, address: int, scan_result: Optional[Dict]) -> Tuple[bool, str]:
        """
        Validate address was actually scanned
        """
        if scan_result is None:
            return (False, "HALLUCINATION: Address not scanned")
        
        scanned_ranges = scan_result.get('scanned_ranges', [])
        for start, end in scanned_ranges:
            if start <= address <= end:
                return (True, f"Address {address} in scanned range [{start}, {end}]")
        
        return (False, f"HALLUCINATION: Address {address} not in scanned ranges")
    
    def check_speculation(self, text: str) -> Tuple[bool, List[str]]:
        """
        Check if text contains speculation phrases
        """
        found_phrases = []
        text_lower = text.lower()
        
        for phrase in self.SPECULATION_PHRASES:
            if phrase in text_lower:
                found_phrases.append(phrase)
        
        return (len(found_phrases) > 0, found_phrases)
    
    def _log_validation(self, flag: str, is_valid: bool, reason: str) -> None:
        self.validation_log.append({
            'timestamp': time.time(),
            'flag': flag,
            'is_valid': is_valid,
            'reason': reason
        })
    
    def get_validation_report(self) -> Dict[str, Any]:
        return {
            'total_validations': len(self.validation_log),
            'valid_count': sum(1 for v in self.validation_log if v['is_valid']),
            'invalid_count': sum(1 for v in self.validation_log if not v['is_valid']),
            'log': self.validation_log
        }


class EvidenceCollector:
    """
    Collect evidence for every action
    Required for anti-hallucination
    """
    
    def __init__(self):
        self.evidence_log: List[Dict] = []
    
    def record_action(self, action_type: str, command: str, output: Any, result: Any) -> Dict:
        """
        Record action with full evidence
        """
        evidence = {
            'timestamp': time.time(),
            'action_type': action_type,
            'command': command,
            'output': str(output),
            'result': result,
            'output_hash': hashlib.sha256(str(output).encode()).hexdigest()[:16]
        }
        
        self.evidence_log.append(evidence)
        return evidence
    
    def get_flag_evidence(self, flag: str) -> Optional[Dict]:
        """
        Get evidence for a specific flag
        """
        for evidence in self.evidence_log:
            if flag in str(evidence.get('output', '')):
                return evidence
        return None
    
    def get_evidence_for_claim(self, claim_type: str, claim_value: Any) -> Optional[Dict]:
        """
        Get evidence for any type of claim
        """
        for evidence in self.evidence_log:
            if claim_type == 'unit_id':
                if f"Unit {claim_value}" in str(evidence.get('command', '')):
                    return evidence
            elif claim_type == 'address':
                if f"addr {claim_value}" in str(evidence.get('command', '')):
                    return evidence
            elif claim_type == 'flag':
                if claim_value in str(evidence.get('output', '')):
                    return evidence
        return None
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate evidence report
        """
        flags_found = []
        for e in self.evidence_log:
            output = str(e.get('output', ''))
            matches = re.findall(r'[a-zA-Z0-9_]+\{[^}]+\}', output)
            for m in matches:
                flags_found.append({
                    'flag': m,
                    'evidence_hash': e['output_hash'],
                    'command': e['command'],
                    'timestamp': e['timestamp']
                })
        
        return {
            'total_actions': len(self.evidence_log),
            'actions_by_type': self._count_by_type(),
            'flags_with_evidence': flags_found,
            'full_log': self.evidence_log
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        counts = {}
        for e in self.evidence_log:
            t = e.get('action_type', 'unknown')
            counts[t] = counts.get(t, 0) + 1
        return counts


class AntiHallucinationWrapper:
    """
    Wrapper that enforces anti-hallucination rules
    Use this to wrap any CTF solver
    """
    
    def __init__(self):
        self.guard = HallucinationGuard()
        self.collector = EvidenceCollector()
    
    def execute_and_validate(self, command: str, executor_func, *args, **kwargs) -> Dict[str, Any]:
        """
        Execute command and validate results
        
        Args:
            command: Command string for logging
            executor_func: Function to execute
            *args, **kwargs: Arguments for executor_func
        
        Returns:
            Dict with validated results
        """
        # Execute
        try:
            result = executor_func(*args, **kwargs)
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'evidence': None
            }
        
        # Record evidence
        evidence = self.collector.record_action(
            action_type='execute',
            command=command,
            output=result,
            result=result
        )
        
        # Extract and validate flags
        validated_flags = []
        output_str = str(result)
        
        flag_matches = re.findall(r'[a-zA-Z0-9_]+\{[^}]+\}', output_str)
        for flag in flag_matches:
            is_valid, reason = self.guard.validate_flag_claim(flag, evidence)
            validated_flags.append({
                'flag': flag,
                'is_valid': is_valid,
                'reason': reason
            })
        
        return {
            'success': True,
            'result': result,
            'evidence': evidence,
            'validated_flags': validated_flags,
            'valid_flag_count': sum(1 for f in validated_flags if f['is_valid'])
        }
    
    def report_flag(self, flag: str) -> Dict[str, Any]:
        """
        Report a flag with full validation
        """
        evidence = self.collector.get_flag_evidence(flag)
        
        if evidence is None:
            return {
                'accepted': False,
                'flag': flag,
                'reason': 'HALLUCINATION: No evidence found for this flag'
            }
        
        is_valid, reason = self.guard.validate_flag_claim(flag, evidence)
        
        if is_valid:
            return {
                'accepted': True,
                'flag': flag,
                'evidence_hash': evidence['output_hash'],
                'command': evidence['command'],
                'reason': reason
            }
        else:
            return {
                'accepted': False,
                'flag': flag,
                'reason': reason
            }


# === CLI Interface ===

if __name__ == '__main__':
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description='🛡️ AI Hallucination Guard')
    parser.add_argument('--validate-flag', help='Validate a flag claim')
    parser.add_argument('--command', help='Command that produced the flag')
    parser.add_argument('--output', help='Output that contains the flag')
    parser.add_argument('--check-speculation', help='Check text for speculation')
    parser.add_argument('--json', action='store_true', help='JSON output')
    
    args = parser.parse_args()
    
    guard = HallucinationGuard()
    
    if args.validate_flag:
        if not args.command or not args.output:
            print("Error: --command and --output required for validation")
            exit(1)
        
        evidence = {
            'command': args.command,
            'output': args.output
        }
        
        is_valid, reason = guard.validate_flag_claim(args.validate_flag, evidence)
        
        result = {
            'flag': args.validate_flag,
            'is_valid': is_valid,
            'reason': reason
        }
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if is_valid:
                print(f"✅ VALID: {args.validate_flag}")
                print(f"   Reason: {reason}")
            else:
                print(f"❌ INVALID: {args.validate_flag}")
                print(f"   Reason: {reason}")
    
    elif args.check_speculation:
        has_speculation, phrases = guard.check_speculation(args.check_speculation)
        
        result = {
            'has_speculation': has_speculation,
            'phrases_found': phrases
        }
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if has_speculation:
                print(f"⚠️ SPECULATION DETECTED: {phrases}")
            else:
                print("✅ No speculation detected")
    
    else:
        parser.print_help()
