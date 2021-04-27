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

--------

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
--------


## Request Scanning IP Adress
`POST /api/scan/{ip}`

--------

## Request Scanning IP Range with CIDR Notation
`POST /api/scan/{ip}/{CIDR_notation}`

--------

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
--------

## Get Pending Tasks
`GET /api/scan/task?skip=0&count=0`
### Response
```json
[
    "123.123.123.123/32",
    "123.123.123.0/24",
]
```

--------

## Remove Pending Task
`DELETE /api/scan/task/{ip}/{CIDR_notation}`

e.g. `DELETE /api/scan/task/123.123.123.0/24`

### Response
```json
{
    "removed_tasks": 1
}
```

--------

## Clear Pending Tasks
`DELETE /api/scan/task/all`

### Response
```json
{
    "removed_tasks": 1024
}
```

--------


## Get All Available Hosts
`GET /api/search/all?skip=0&count=10`

Just alias of `/api/scan/0.0.0.0/0?online_only=1`

--------


## Search by IP Range with CIDR Notation
`GET /api/scan/{ip}/{CIDR_notation}?skip=0&count=10&online_only=1`

e.g. `GET /api/scan/123.123.123.123/24`



### Response
```json
[
    {
        "addr": "123.123.123.123",
        "last_update": 1618933373681,
        "opened_ports": [80, 443, 22],
        "services": ["Nginx 1.4.0", "OpenSSH 7.0"],
        "vulnerabilities": 13
    },
    {
        "addr": "100.100.100.100",
        "last_update": 1618933373681,
        "opened_ports": [80, 22],
        "services": ["PHP 7.0", "OpenSSH 7.2"],
        "vulnerabilities": 21
    }
]
```

--------


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

--------

## Search by Port
`GET /api/search/port/{port}`


--------

## Get System Stats
`GET /api/stats/system`
### Response
```json
{
    "cpu_usage": 0,
    "total_memory_kb": 0,
    "used_memory_kb": 0,
    "total_swap_kb": 0,
    "used_swap_kb": 0,
    "network_in_bytes": 0,
    "network_out_bytes": 0,
    "load_one": 0,
    "load_five": 0,
    "load_fifteen": 0
}
```

--------

## Get Scheduler Stats
`GET /api/stats/scheduler`
### Response
```json
{
    "pending_addrs": 0,
    "tasks_per_second": 0,
    "ip_per_second": 0,
}
```