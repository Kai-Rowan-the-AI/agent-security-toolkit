#!/usr/bin/env python3
"""Skill Auditor - Scan skills before installation.

Part of the Agent Security Toolkit - helping AI agents verify skills before installation.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from typing import List, Tuple, Optional
from pathlib import Path


@dataclass
class Finding:
    """A security finding from the audit."""
    severity: str  # 'critical', 'warning', 'info'
    category: str
    description: str
    pattern: str
    line_number: Optional[int] = None
    line_content: Optional[str] = None
    
    def to_dict(self):
        return asdict(self)


# Security patterns organized by severity
SECURITY_PATTERNS = {
    'critical': [
        (r'rm\s+-rf\s+/', 'Dangerous deletion', 'Filesystem'),
        (r'rm\s+-rf\s+~', 'Home directory deletion', 'Filesystem'),
        (r'>\s*/dev/sd[a-z]', 'Raw disk write', 'Filesystem'),
        (r'mkfs\.\w+', 'Filesystem format', 'Filesystem'),
        (r':\(\)\{\s*:\|:\s*\}', 'Fork bomb', 'DoS'),
        (r'dd\s+if=.*of=/dev/', 'Direct disk write', 'Filesystem'),
    ],
    'warning': [
        (r'curl\s+.*\|\s*(ba)?sh', 'Pipe to shell', 'Execution'),
        (r'wget\s+.*\|\s*(ba)?sh', 'Pipe to shell', 'Execution'),
        (r'eval\s*\(', 'Eval usage', 'Execution'),
        (r'exec\s*\(', 'Exec usage', 'Execution'),
        (r'system\s*\(', 'System call', 'Execution'),
        (r'subprocess\.call', 'Subprocess execution', 'Execution'),
        (r'os\.system', 'OS system call', 'Execution'),
        (r'__import__\s*\(', 'Dynamic import', 'Execution'),
        (r'compile\s*\(', 'Dynamic compilation', 'Execution'),
        (r'code\.interact', 'Interactive shell', 'Execution'),
        (r'pty\.spawn', 'PTY spawn', 'Execution'),
    ],
    'info': [
        (r'https?://[^\s\"]+', 'External URL', 'Network'),
        (r'fetch\s*\(', 'Fetch API', 'Network'),
        (r'requests\.', 'HTTP request', 'Network'),
        (r'urllib', 'URL library', 'Network'),
        (r'socket\.', 'Socket usage', 'Network'),
        (r'localhost', 'Localhost reference', 'Network'),
        (r'127\.0\.0\.1', 'Loopback reference', 'Network'),
    ]
}


def audit_skill_file(skill_file: str) -> Tuple[List[Finding], List[str]]:
    """Audit a skill.md file for security issues.
    
    Args:
        skill_file: Path to the skill file to audit
        
    Returns:
        Tuple of (findings, errors)
    """
    findings = []
    errors = []
    
    path = Path(skill_file)
    if not path.exists():
        errors.append(f"File not found: {skill_file}")
        return findings, errors
    
    try:
        content = path.read_text(encoding='utf-8')
        lines = content.split('\n')
    except Exception as e:
        errors.append(f"Error reading file: {e}")
        return findings, errors
    
    # Check patterns by severity
    for severity, patterns in SECURITY_PATTERNS.items():
        for pattern, description, category in patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=severity,
                        category=category,
                        description=description,
                        pattern=pattern,
                        line_number=line_num,
                        line_content=line.strip()[:100]  # Truncate long lines
                    ))
    
    return findings, errors


def format_text_output(skill_file: str, findings: List[Finding], errors: List[str]) -> str:
    """Format audit results as human-readable text."""
    output = []
    
    output.append(f"\n🔍 Agent Security Toolkit - Skill Audit")
    output.append(f"File: {skill_file}")
    output.append("=" * 60)
    
    if errors:
        output.append("\n❌ Errors:")
        for error in errors:
            output.append(f"  • {error}")
    
    if not findings:
        output.append("\n✅ No security issues found!")
        return '\n'.join(output)
    
    # Group by severity
    severity_icons = {'critical': '🔴', 'warning': '🟡', 'info': '🔵'}
    
    for severity in ['critical', 'warning', 'info']:
        severity_findings = [f for f in findings if f.severity == severity]
        if severity_findings:
            output.append(f"\n{severity_icons[severity]} {severity.upper()} ({len(severity_findings)}):")
            for finding in severity_findings:
                loc = f" (line {finding.line_number})" if finding.line_number else ""
                output.append(f"  [{finding.category}]{loc} {finding.description}")
                if finding.line_content:
                    output.append(f"    → {finding.line_content}")
    
    output.append("\n" + "=" * 60)
    
    # Summary and recommendation
    critical = len([f for f in findings if f.severity == 'critical'])
    warnings = len([f for f in findings if f.severity == 'warning'])
    
    if critical > 0:
        output.append(f"\n⛔ CRITICAL ISSUES FOUND: {critical}")
        output.append("   DO NOT INSTALL without thorough review!")
    elif warnings > 0:
        output.append(f"\n⚠️  {warnings} warning(s) found. Review recommended.")
    else:
        output.append("\nℹ️  Informational findings only.")
    
    return '\n'.join(output)


def format_json_output(skill_file: str, findings: List[Finding], errors: List[str]) -> str:
    """Format audit results as JSON."""
    result = {
        "file": skill_file,
        "timestamp": None,  # Could add ISO timestamp
        "summary": {
            "critical": len([f for f in findings if f.severity == 'critical']),
            "warning": len([f for f in findings if f.severity == 'warning']),
            "info": len([f for f in findings if f.severity == 'info']),
            "total": len(findings)
        },
        "findings": [f.to_dict() for f in findings],
        "errors": errors,
        "safe_to_install": len([f for f in findings if f.severity == 'critical']) == 0
    }
    return json.dumps(result, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Audit skill files for security issues before installation.",
        epilog="Part of the Agent Security Toolkit - keeping AI agents safe."
    )
    parser.add_argument("skill_file", help="Path to skill.md file to audit")
    parser.add_argument(
        "-j", "--json", 
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "-o", "--output",
        help="Write output to file (default: stdout)"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with error code if any warnings or critical issues found"
    )
    
    args = parser.parse_args()
    
    findings, errors = audit_skill_file(args.skill_file)
    
    # Generate output
    if args.json:
        output = format_json_output(args.skill_file, findings, errors)
    else:
        output = format_text_output(args.skill_file, findings, errors)
    
    # Write or print
    if args.output:
        Path(args.output).write_text(output)
        print(f"Audit results written to: {args.output}")
    else:
        print(output)
    
    # Exit code
    if errors:
        sys.exit(2)
    if args.strict and any(f.severity in ('critical', 'warning') for f in findings):
        sys.exit(1)
    if any(f.severity == 'critical' for f in findings):
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()
