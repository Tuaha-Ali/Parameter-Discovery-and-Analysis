# Parameter-Discovery-and-Analysis

# Parameter Discovery Methodology
    Parameter Sources:
 ├── URL query parameters (?id=1&name=test)
 ├── POST body parameters (form data, JSON)
 ├── HTTP headers (custom headers)
 ├── Cookies (session, preferences)
 ├── Path parameters (/api/users/123)
 ├── Fragment identifiers (#section)
 ├── WebSocket messages
 └── Hidden/undocumented parameters
# Arjun - Parameter Discovery
 Basic parameter discovery
arjun -u https://target.com/endpoint

 **With custom wordlist**
arjun -u https://target.com/endpoint -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

 **Multiple URLs**
arjun -i urls.txt -oJ arjun_results.json

 **Specific HTTP methods**
arjun -u https://target.com/api/users -m POST
arjun -u https://target.com/api/users -m JSON  # JSON body

 **With headers**
arjun -u https://target.com/endpoint --headers "Cookie: session=abc;Authorization: Bearer token"

 **Rate limiting**
arjun -u https://target.com/endpoint --rate 50

 **Stable mode (more accurate, slower)**
arjun -u https://target.com/endpoint --stable

 **Output formats**
arjun -u https://target.com/endpoint -oJ output.json
arjun -u https://target.com/endpoint -oT output.txt

 # x8 - Hidden Parameter Discovery
    x8 - fast parameter discovery
x8 -u "https://target.com/endpoint" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

 **With custom wordlist**
x8 -u "https://target.com/api/users" \
  -w params.txt \
  -X POST \
  -H "Content-Type: application/json"

 **Test headers as parameters**
x8 -u "https://target.com/endpoint" -w headers.txt --headers

 **Multiple URLs**
x8 -u "https://target.com/endpoint1" -u "https://target.com/endpoint2" -w params.txt

 # Burp Suite Parameter Discovery
  Param Miner Extension
 Extensions → BApp Store → Install "Param Miner"

# Usage:
# Right-click request → Extensions → Param Miner → Guess params
 Options:
   - Guess GET params
   - Guess POST params  
   - Guess headers
   - Guess cookies

# Param Miner techniques:
 1. Adds parameters one at a time
 2. Compares response to baseline
 3. Reports parameters that change the response

# Burp Scanner parameter handling:
 Scanner → Scan configuration → Audit optimization
 - Follow redirects: Always
 - Include parameters: All
 Handle application errors: Report

# Active Scan:
 Right-click request → Scan → Active scan
 Tests all discovered parameters for vulnerabilities

# Parameter Wordlists
 Burp Suite built-in
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Common parameters
 id, user_id, uid, account_id, item_id     → IDOR
 url, redirect, next, return, goto, ref     → Open Redirect, SSRF
 search, q, query, keyword, s, term        → XSS, SQLi
 file, path, page, template, include       → LFI/RFI
 cmd, exec, command, run                   → Command Injection
 email, username, user, login              → Account Enumeration
 sort, order, column, dir                  → SQLi (ORDER BY)
 callback, jsonp, cb                       → JSONP abuse
 format, type, output                      → XXE, SSRF
 debug, test, admin                        → Debug mode
 token, csrf, nonce                        → CSRF bypass
 lang, language, locale                    → LFI
 action, do, func, method                  → Function abuse
 role, admin, is_admin, privilege          → Privilege escalation
 price, amount, quantity, discount         → Business logic
 webhook, notify_url, callback_url         → SSRF
# From crawled content
cat all_urls.txt | grep -oP '[?&]\K[^=]+' | sort | uniq -c | sort -rn > discovered_params.txt
# From JavaScript files
cat js_files/*.js | grep -oP '["'"'"']([a-zA-Z_][a-zA-Z0-9_]{2,30})["'"'"']\s*:' | \
  sed "s/[\"':]//g" | sort -u > js_params.txt
# Combine
cat /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    discovered_params.txt js_params.txt | sort -u > custom_params.txt

# JSON Parameter Discovery
# Test JSON body parameters
curl -s -X POST "https://target.com/api/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"test":"value"}'

# Common JSON parameters to try
 {"admin": true}
 {"role": "admin"}
 {"debug": true}
 {"verbose": true}
 {"internal": true}
 {"is_admin": 1}
 {"user_id": 1}
 {"id": 1}

** Mass assignment testing**
 Find what the normal request looks like
curl -s https://target.com/api/profile -H "Authorization: Bearer TOKEN"
 **Try adding extra fields**
curl -s -X PUT https://target.com/api/profile \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","is_admin":true,"verified":true}'

 **JSON parameter pollution**
 {"user_id": 1, "user_id": 2}  # Which one wins?
 {"user": {"id": 1}, "user": {"id": 2}}

 **Header-Based Parameter Discovery**
   Custom headers that may change behavior
HEADERS="X-Forwarded-For X-Forwarded-Host X-Original-URL X-Rewrite-URL
 X-Custom-IP-Authorization X-Real-IP X-Remote-IP X-Remote-Addr
 X-Client-IP X-Host True-Client-IP Cluster-Client-IP
 X-Forwarded-Port X-Forwarded-Proto X-Forwarded-Scheme
 X-Original-Host X-Forwarded-Server
 X-Debug X-Debug-Mode X-Test
 X-Api-Version Api-Version Accept-Version
 X-Requested-With X-HTTP-Method-Override
 Content-Type Accept"

for header in $HEADERS; do
    response=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
      -H "$header: test_value_12345" https://target.com/endpoint 2>/dev/null)
    echo "$header → $response"
done

 **X-HTTP-Method-Override**
curl -s -X POST https://target.com/api/users \
  -H "X-HTTP-Method-Override: DELETE"
curl -s -X POST https://target.com/api/users \
  -H "X-HTTP-Method-Override: PUT"

 **Content-Type variations**
curl -s -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" -d '{"test":1}'
curl -s -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/xml" -d '<test>1</test>'
curl -s -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/x-www-form-urlencoded" -d 'test=1'

   # Cookie Parameter Analysis
 **Extract all cookies**
 
curl -sI https://target.com | grep -i "set-cookie"

 **Analyze cookie value**s
 Session cookies: random, high entropy
 Preference cookies: may contain user input
 Tracking cookies: analytics data
 Debug cookies: may enable debug mode

 **Test cookie parameters**
 Add debug cookies
curl -s -b "debug=true" https://target.com
curl -s -b "admin=true" https://target.com
curl -s -b "role=admin" https://target.com
curl -s -b "test=1" https://target.com
curl -s -b "internal=1" https://target.com

 **Cookie injection points**
 Try injecting into existing cookie values
curl -s -b "lang=en' OR 1=1--" https://target.com
curl -s -b "theme=<script>alert(1)</script>" https://target.com

# GraphQL Parameter Enumeration
   **GraphQL field discovery**
   **Introspection query**
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' \
  https://target.com/graphql | jq '.data.__schema.types[] | select(.fields != null) | {name, fields: [.fields[].name]}'

 **Field suggestion exploitation**
 Some GraphQL servers suggest similar field names on typos
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"query":"{ user { passwor } }"}' \
  https://target.com/graphql
 Response: "Did you mean 'password'?"

 **Brute force fields when introspection is disabled**
 clairvoyance
python3 clairvoyance.py -w field_wordlist.txt -d https://target.com/graphql

 **Common GraphQL fields to test**:
 user { id name email password role admin token }
 users { id name email role }
 config { debug secret key }
 flag { value }
 admin { users settings }

# Parameter Analysis Script(bash script)

   #!/bin/bash
 param_analysis.sh
TARGET=$1
ENDPOINT=$2
OUTDIR="recon/${TARGET}/params"
mkdir -p $OUTDIR

echo "=== Parameter Analysis: $ENDPOINT ==="

 **Baseline response**
echo "[1/4] Getting baseline..."
BASELINE_SIZE=$(curl -s "https://$TARGET$ENDPOINT" | wc -c)
BASELINE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$ENDPOINT")
echo "Baseline: $BASELINE_CODE ($BASELINE_SIZE bytes)"

 #!/bin/bash
# param_analysis.sh
TARGET=$1
ENDPOINT=$2
OUTDIR="recon/${TARGET}/params"
mkdir -p $OUTDIR

echo "=== Parameter Analysis: $ENDPOINT ==="

# Baseline response
echo "[1/4] Getting baseline..."
BASELINE_SIZE=$(curl -s "https://$TARGET$ENDPOINT" | wc -c)
BASELINE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$ENDPOINT")
echo "Baseline: $BASELINE_CODE ($BASELINE_SIZE bytes)"

# Test GET parameters
echo "[2/4] Testing GET parameters..."
while read param; do
    resp_size=$(curl -s "https://$TARGET${ENDPOINT}?${param}=test123" | wc -c)
    resp_code=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET${ENDPOINT}?${param}=test123")
    if [ "$resp_size" != "$BASELINE_SIZE" ] || [ "$resp_code" != "$BASELINE_CODE" ]; then
        echo "[+] Parameter affects response: $param (code=$resp_code, size=$resp_size)"
        echo "$param" >> $OUTDIR/valid_params.txt
    fi
done < /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Test POST parameters
echo "[3/4] Testing POST parameters..."
while read param; do
    resp_size=$(curl -s -X POST "https://$TARGET$ENDPOINT" -d "${param}=test123" | wc -c)
    if [ "$resp_size" != "$BASELINE_SIZE" ]; then
        echo "[+] POST parameter affects response: $param (size=$resp_size)"
        echo "$param" >> $OUTDIR/valid_post_params.txt
    fi
done < /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Test custom headers
echo "[4/4] Testing header parameters..."
for header in X-Forwarded-For X-Original-URL X-Rewrite-URL X-Debug X-Custom-IP-Authorization; do
    resp_size=$(curl -s -H "$header: 127.0.0.1" "https://$TARGET$ENDPOINT" | wc -c)
    if [ "$resp_size" != "$BASELINE_SIZE" ]; then
        echo "[+] Header affects response: $header (size=$resp_size)"
        echo "$header" >> $OUTDIR/valid_headers.txt
    fi
done

echo "[*] Results saved to $OUTDIR/"
echo "[2/4] Testing GET parameters..."
while read param; do
    resp_size=$(curl -s "https://$TARGET${ENDPOINT}?${param}=test123" | wc -c)
    resp_code=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET${ENDPOINT}?${param}=test123")
    if [ "$resp_size" != "$BASELINE_SIZE" ] || [ "$resp_code" != "$BASELINE_CODE" ]; then
        echo "[+] Parameter affects response: $param (code=$resp_code, size=$resp_size)"
        echo "$param" >> $OUTDIR/valid_params.txt
    fi
done < /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

 **Test POST parameters**
echo "[3/4] Testing POST parameters..."
while read param; do
    resp_size=$(curl -s -X POST "https://$TARGET$ENDPOINT" -d "${param}=test123" | wc -c)
    if [ "$resp_size" != "$BASELINE_SIZE" ]; then
        echo "[+] POST parameter affects response: $param (size=$resp_size)"
        echo "$param" >> $OUTDIR/valid_post_params.txt
    fi
done < /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

 **Test custom headers**
echo "[4/4] Testing header parameters..."
for header in X-Forwarded-For X-Original-URL X-Rewrite-URL X-Debug X-Custom-IP-Authorization; do
    resp_size=$(curl -s -H "$header: 127.0.0.1" "https://$TARGET$ENDPOINT" | wc -c)
    if [ "$resp_size" != "$BASELINE_SIZE" ]; then
        echo "[+] Header affects response: $header (size=$resp_size)"
        echo "$header" >> $OUTDIR/valid_headers.txt
    fi
done

echo "[*] Results saved to $OUTDIR/"
