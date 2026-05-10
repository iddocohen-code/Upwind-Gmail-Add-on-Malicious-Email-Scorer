# analyzers/content_modules/attachment_analyzer.py
import requests
import re
from config import VT_API_KEY

def check_malicious_extensions(filename):
    """
    HEURISTICS: Checks for inherently dangerous file extensions.
    Returns True if the extension is blacklisted.
    """
    if not filename:
        return False
        
    filename = filename.lower()
    # List of highly executable/dangerous extensions in an email context
    dangerous_exts = [
        '.exe', '.vbs', '.scr', '.bat', '.cmd', '.js', '.jse', '.wsf', '.wsh', 
        '.ps1', '.hta', '.jar', '.reg', '.msi', '.pif', '.com'
    ]
    
    return any(filename.endswith(ext) for ext in dangerous_exts)

def check_double_extensions(filename):
    """
    HEURISTICS: Detects the 'double extension' trick (e.g., invoice.pdf.exe).
    Attackers use this to hide the true executable nature of a file.
    Returns True if a double extension is found leading to an executable.
    """
    if not filename:
        return False
        
    filename = filename.lower()
    # Matches patterns like .pdf.exe, .doc.vbs, etc.
    # We look for a harmless extension followed by a dangerous one at the end.
    harmless = r'(\.pdf|\.doc|\.docx|\.xls|\.xlsx|\.txt|\.jpg|\.png)'
    dangerous = r'(\.exe|\.vbs|\.scr|\.bat|\.js|\.wsf|\.cmd)$'
    
    pattern = harmless + dangerous
    return bool(re.search(pattern, filename))

def get_hash_reputation(file_hash):
    """
    THREAT INTEL: Queries VirusTotal using the SHA-256 hash.
    Returns the number of engines that flagged the file as malicious.
    """
    if not file_hash or file_hash == "":
        return 0
        
    try:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}", 
            headers=headers, 
            timeout=5
        )
        if response.status_code == 200:
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return stats.get('malicious', 0) + stats.get('suspicious', 0)
        return 0
    except Exception as e:
        print(f"[!] Hash Threat Intel Error: {e}")
        return 0

def analyze(attachments):
    """
    Main entry point for evaluating email attachments.
    Returns a score (0-100) and a list of specific findings.
    """
    if not attachments or len(attachments) == 0:
        return 100, []

    score = 100
    findings = []
    
    print(f"\n[BACKEND LOG] ATTACHMENTS: Analyzing {len(attachments)} files...")

    for att in attachments:
        filename = att.get('name', '')
        file_hash = att.get('hash', '')
        
        print(f"  -> Inspecting: {filename} (Hash: {file_hash[:8]}...)")

        # 1. Structural Heuristics: Blacklisted Extensions
        if check_malicious_extensions(filename):
            print(f"  [BACKEND LOG] ATTACHMENTS: ALERT! Dangerous extension found: {filename}")
            score = 0
            findings.append(f"Blocked executable attachment: '{filename}'.")
            return score, findings # Immediate Zero-Trust kill

        # 2. Structural Heuristics: Double Extensions
        if check_double_extensions(filename):
            print(f"  [BACKEND LOG] ATTACHMENTS: ALERT! Deceptive double extension found: {filename}")
            score = 0
            findings.append(f"Deceptive file naming detected (double extension): '{filename}'.")
            return score, findings # Immediate Zero-Trust kill

        # 3. Threat Intel: Hash Verification
        if file_hash:
            malicious_flags = get_hash_reputation(file_hash)
            if malicious_flags > 0:
                print(f"  [BACKEND LOG] ATTACHMENTS: ALERT! Known malware signature detected.")
                score = 0
                findings.append(f"Attachment '{filename}' matches a known malware signature.")
                return score, findings # Immediate Zero-Trust kill

    return score, findings