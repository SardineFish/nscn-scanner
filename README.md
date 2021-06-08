# NSCN Net Scanner & Vulnerability Analyser

A platform used to scan and report vulnerabilities on remote device in specific network space.

## Build
### Requirement
- Rust 1.52 (No Shadowsocks proxy support, build with args `--no-default-features`)
- Rust nightly (Support shadowsocks, default)

### Build Command
Recommend build optmised binary with `--release` on production environment.

Build with shadowsocks support by nightly rust toolchain
```shell
$ cargo +nightly build --release
```
Build without shadowsocks support in stable rust toolchain
```shell
$ cargo build --release --no-default-features
```

## Run
### Runtime Requirement
- OpenSSL, install with `apt-get instal libssl-dev`
- Config file named `config.json` in project root directory

### Run CLI
```shell
$ cargo run
```

#### CLI Arguments
Specify config file
```shell
$ cargo run --release -- -c /path/to/config.json
```

Specify node role
```shell
$ cargo run --release -- --role Standalone
```

For more args, see:
```shell
$ cargo run --release -- --help
```

### Configuration File
See `config-example.json` for example.
```js
{
    "mongodb": "mongodb://127.0.0.1/nscn",
    "redis": "redis://127.0.0.1/0",
    "listen": "127.0.0.1:3000", // The API server will listen on this address and port, Make sure other Workers, Master or WebUI can connect to this address.
    "role": "Standalone", // Master | Worker | Standalone (* both master and worker)
    "workers": [
        "<worker_address>:<port>" // (optional) The `listen` address of the worker API server. Connect to Worker from Master
    ],
    "master": "127.0.0.1:3001" // (optional) Connect to Master from Worker
    "proxy": {
        "http": { // HTTP proxy pool config, use with https://github.com/jhao104/proxy_pool
            "update": false,
            "fetch_addr": "http://localhost:5000/proxy_pool/get_all/",
            "update_interval": 60,
            "http_validate": [
                "http://www.baidu.com"
            ],
            "https_validate": "www.baidu.com:443"
        },
        "socks5": { // Socks5 proxy pool used with http://webapi.http.zhimacangku.com/
            "enabled": true,
            "fetch": "<fetch_url>", // Fetch api in json format with expire time.
            "pool_size": 0, // Keep N socks5 proxies in pool to perform load balance
            "servers": [ // Manually add socks5 proxies into pool, ignoreing pool size
                "127.0.0.1:1080"
            ]
        },
        "shadowsocks": [ // Shadowsocks servers
            {
                "address": "127.0.0.1",
                "port": 1234,
                "password": "<password>",
                "method": "aes-256-cfb"
            }
        ]
    },
    "scanner": {
        "ports": { // Specify which scanners should be used to scan on a TCP port
            "80": ["http"],
            "443": ["tls"],
            "21": ["ftp"],
            "22": ["ssh"],
            "3000": [ "http", "tls" ] // Scan 3000/tcp with both http and tls scanner
        },
        "config": { // Per scanner config
            "http": {
                "enabled": true,
                "use_proxy": true,
                "proxy": "Shadowsocks", // None | Socks5 | Shadowsocks | Http
                "timeout": 5
            },
            "tls": {
                "enabled": true,
                "use_proxy": true,
                "proxy": "Shadowsocks",
                "timeout": 5
            },
            "ftp": {
                "enabled": true,
                "use_proxy": true,
                "proxy": "Shadowsocks",
                "timeout": 5
            },
            "ssh": {
                "enabled": true,
                "use_proxy": true,
                "proxy": "Shadowsocks",
                "timeout": 5
            }
        },
        "scheduler": {
            "enabled": true,
            "max_tasks": 20000,
            "fetch_count": 16,
            "fetch_threshold": 8
        },
        "save": {
            "collection": "scan", // Not implement yet
            "save_failure": true // Save failed error info or not, turn off to improve performance of database.
        }
    },
    "analyser": {
        "analyse_on_scan": false, // Not implement yet.
        "externals": {
            "wappanalyser_rules": "./thirdparty/wappanalyser/technologies.json",
            "ftp_rules": "./rules/ftp.json",
            "ssh_rules": "./rules/ssh.json",
            "city_coords": "./china-cities.json"
        },
        "scheduler": {
            "enabled": true,
            "max_tasks": 32,
            "fetch_count": 16,
            "fetch_threshold": 8
        },
        "save": "analyse", // Not implement yet
        "vuln_search": {
            "exploitdb": "./thirdparty/exploitdb/searchsploit"
        }
    },
    "stats": {
        "sys_update_interval": 1000,
        "scheduler_update_interval": 10000
    }
}
```