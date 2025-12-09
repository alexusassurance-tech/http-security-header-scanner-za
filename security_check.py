import requests
import sys

def check_security_headers(url):
    """
    Checks for the presence and configuration of essential security headers.
    """
    # Ensure URL has scheme for requests
    if not url.startswith('http'):
        url = 'https://' + url

    # Define the essential headers we expect to see
    required_headers = {
        'Strict-Transport-Security': 'HSTS is missing or misconfigured.',
        'Content-Security-Policy': 'CSP is missing. Crucial against XSS attacks.',
        'X-Frame-Options': 'XFO is missing. Crucial against clickjacking.',
        'X-Content-Type-Options': 'XCTO is missing or misconfigured.',
    }

    print(f"\n--- Scanning: {url} ---\n")
    
    try:
        # We only need the headers, so use head()
        response = requests.head(url, allow_redirects=True, timeout=10)
        
        # Make sure we check the final destination headers after redirects
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        missing_or_bad_headers = {}

        for header_name, error_message in required_headers.items():
            normalized_name = header_name.lower()
            
            if normalized_name not in headers:
                missing_or_bad_headers[header_name] = error_message
                continue
            
            # Additional check for specific header values
            value = headers[normalized_name]
            
            if header_name == 'Strict-Transport-Security':
                # Check for includeSubDomains and a long max-age (1 year min)
                if 'includesubdomains' not in value.lower() or 'max-age' not in value.lower() or int(value.split('max-age=')[1].split(';')[0].strip()) < 31536000:
                    missing_or_bad_headers[header_name] = "HSTS is present but improperly configured (must include subdomains and max-age >= 31536000)."
            
            elif header_name == 'X-Content-Type-Options' and 'nosniff' not in value.lower():
                missing_or_bad_headers[header_name] = "X-Content-Type-Options is present but 'nosniff' directive is missing."

        if not missing_or_bad_headers:
            print("✅ ALL ESSENTIAL SECURITY HEADERS ARE PRESENT AND PROPERLY CONFIGURED.")
        else:
            print("❌ SECURITY VULNERABILITY ALERT: Missing or bad headers detected:")
            for header, issue in missing_or_bad_headers.items():
                print(f"   - {header}: {issue}")

        print("\n--- Raw Headers for Debugging ---")
        for k, v in response.headers.items():
            print(f"{k}: {v}")

    except requests.exceptions.RequestException as e:
        print(f"❌ ERROR: Could not connect to {url}. Details: {e}")
    except Exception as e:
        print(f"❌ AN UNEXPECTED ERROR OCCURRED: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python security_check.py <URL>")
        print("Example: python security_check.py google.com")
        sys.exit(1)
        
    target_url = sys.argv[1]
    check_security_headers(target_url)

