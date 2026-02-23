#!/usr/bin/env python3
"""Skill Auditor - Scan skills before installation."""

import sys
import re

def audit_skill(skill_file):
    """Audit a skill.md file for security issues."""
    issues = []
    
    with open(skill_file, 'r') as f:
        content = f.read()
    
    # Check for dangerous patterns
    dangerous_patterns = [
        (r'rm\s+-rf', 'Dangerous deletion command'),
        (r'curl.*\|.*sh', 'Pipe from curl to shell'),
        (r'eval\s*\(', 'Eval usage'),
        (r'exec\s*\(', 'Exec usage'),
    ]
    
    for pattern, description in dangerous_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append(f"⚠️  {description}: {pattern}")
    
    # Check for network calls
    network_patterns = [
        (r'https?://', 'External network call'),
        (r'fetch\s*\(', 'Fetch API usage'),
    ]
    
    for pattern, description in network_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            issues.append(f"ℹ️  {description}: {pattern}")
    
    return issues

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: skill-audit.py <skill.md>")
        sys.exit(1)
    
    skill_file = sys.argv[1]
    issues = audit_skill(skill_file)
    
    if issues:
        print(f"\n🔍 Audit Results for {skill_file}:")
        print("=" * 50)
        for issue in issues:
            print(issue)
        print("\n⚠️  Review recommended before installation!")
    else:
        print(f"\n✅ {skill_file} passed basic audit")
