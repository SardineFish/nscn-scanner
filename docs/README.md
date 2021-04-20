## Get Statistics
`GET /api/scan/stats`

### Response
```json
{
    "total_scan": 0,
    "scan_per_seconds": 0,
    "available_servers": 0,
    "total_vulnerabilities": 0,
}
```

## Query by IP Address
`GET /api/scan/{ip}`

### Response

```json
[{
    "addr": "123.123.123.123",
    "services": {
        "Nginx": {
            "name": "Nginx",
            "version": "1.4.0",
            "vulnerabilities": [
                {
                    "id": "CVE-XXXX-XXXX",
                    "title": "Some Vulnerability of Nginx 1.4.0",
                    "url": "http://example.com"
                },
                {
                    "id": "EDB-XXXX",
                    "title": "Another Vulnerability of Nginx 1.4.0",
                    "url": "http://example.com"
                }
            ]
        },
        "OpenSSH": {
            "name": "OpenSSH",
            "version": "",
            "vulnerabilities": []
        }
    },
    "opened_ports": [80, 443, 21, 22],
    "http_response": {
        "status": "200",
        "header": {
            "Server": "Nginx",
            "Content-Type": "text/html"
        }
    },
    "https_certificate": "<In X.509 format>",
    "ftp_access": "Anonymous",
    "ssh_server": "OpenSSH 7.0"
}]
```


## Query by IP Range with CIDR Notation
`GET /api/scan/{ip}/{CIDR_notation}?skip=0&count=10`

e.g. `GET /api/scan/123.123.123.123/24`


## Request Scanning IP Adress
`POST /api/scan/{ip}`

## Request Scanning IP Range with CIDR Notation
`POST /api/scan/{ip}/{CIDR_notation}`

## Request Scanning IP from List URL
`POST /api/scan/list`
### Request
```json
{
    "fetch_urls": [
        "https://example.com/addr_list1.txt",
        "https://example.com/addr_list2.txt"
    ]
}
```

## Get All Available Hosts
`GET /api/search/all?skip=0&count=10`

### Response
```json
[
    {
        "addr": "123.123.123.123",
        "opened_ports": [80, 443, 22],
        "services": ["Nginx 1.4.0", "OpenSSH 7.0"],
        "vulnerabilities": 13
    },
    {
        "addr": "100.100.100.100",
        "opened_ports": [80, 22],
        "services": ["PHP 7.0", "OpenSSH 7.2"],
        "vulnerabilities": 21
    }
]
```


## Search by Service Name
`GET /api/search/service/{service_name}?skip=0&count=10`

`GET /api/search/service/{service_name}/{version}?skip=0&count=10`

### Response
```json
[
    {
        "addr": "123.123.123.123",
        "opened_ports": [80, 443, 22],
        "services": ["Nginx 1.4.0", "OpenSSH 7.0"],
        "vulnerabilities": 13
    },
    {
        "addr": "100.100.100.100",
        "opened_ports": [80, 22],
        "services": ["PHP 7.0", "OpenSSH 7.2"],
        "vulnerabilities": 21
    }
]
```




