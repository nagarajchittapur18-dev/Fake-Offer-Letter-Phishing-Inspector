import os
import sys

# Add backend directory to sys.path so we can import services
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.domain_checker import extract_domain, check_domain
from services.heuristics import analyze_text

def test_pipeline():
    sample_text = """
    Congratulations! You have been selected for an immediate hire at our company without interview.
    Please contact HR on Telegram to proceed. We will send you a check for equipment purchase reimbursement.
    Reach out to our recruiter at fake.recruiter@gmail.com.
    """
    
    # 1. Extract domain
    domain = extract_domain(sample_text)
    assert domain == "gmail.com", f"Expected gmail.com, got {domain}"
    
    # 2. Domain checks
    domain_info = check_domain(domain)
    assert domain_info['domain'] == "gmail.com"
    # Note: gmail.com age is well over 90 days, penalty should be 0 unless whois fails (then 10).
    
    # 3. Heuristics analysis
    heuristics_info = analyze_text(sample_text, domain)
    
    total_penalty = domain_info['penalty'] + heuristics_info['heuristics_penalty']
    
    # Expected findings:
    # - Payment demand (check, equipment purchase, reimbursement)
    # - Channel (immediate hire, without interview, Telegram)
    # - Domain spoofing (gmail.com)
    assert len(heuristics_info['findings']) == 3, f"Expected 3 findings, got {len(heuristics_info['findings'])}"
    assert heuristics_info['heuristics_penalty'] == 85, f"Expected 85 penalty (30+30+25), got {heuristics_info['heuristics_penalty']}"
    
    print("Test passed successfully.")
    print("Domain Info:", domain_info)
    print("Heuristics Info:", heuristics_info)
    print("Total Risk Penalty:", total_penalty)

if __name__ == "__main__":
    test_pipeline()
