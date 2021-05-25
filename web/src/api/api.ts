import { api, Validator, ParamInfo, DeclareQuery } from "./api-builder";

const ipv4Validator: Validator<string> = (key, value) =>
{
    const parts = value.split(".");
    if (parts.length !== 4)
        throw new Error(`Invalid IPv4 format '${value}' in field '${key}'`);
    if (!parts.map(t => parseInt(t)).every(t => t >= 0 && t < 256))
        throw new Error(`Invalid IPv4 format '${value}' in field '${key}'`);
    return value;
}

const IPV4Field: ParamInfo<"string"> = {
    type: "string",
    validator: ipv4Validator,
}

export type NetScanResult<T> =
    {
        proxy: string,
        time: { $date: string },
    } & ({
        result: "Ok",
        data: T
    } | {
        result: "Err",
        data: string,
    });

export interface ScanResult
{
    addr: string,
    last_update: number,
    opened_ports: number[],
    http_results: NetScanResult<{
        status: number,
        headers: Record<string, string[]>,
        body: string,
    }>[];
    https_results: NetScanResult<{ cert: string }>[],
    ftp_results: NetScanResult<{
        handshake_code: number,
        handshake_text: string,
        access: "Anonymous" | "Login",
    }>[];
    ssh_results: NetScanResult<{
        protocol: {
            version: string,
            software: string,
            comments: string,
        },
        algorithm: {
            kex: string[],
            host_key: string[],
            encryption_client_to_server: string[],
            encryption_server_to_client: string[],
            mac_client_to_server: string[],
            mac_server_to_client: string[],
            compression_client_to_server: string[],
            compression_server_to_client: string[],
            languages_client_to_server: string[],
            languages_server_to_client: string[],
        }
    }>[];
    services: Record<string, {
        name: string,
        version: string,
        vulns: string[],
    }>,
    vulns: Record<string, {
        id: string,
        title: string,
        url: string
    }>,
}

export interface BreifResult
{
    addr: string,
    last_update: number,
    opened_ports: number[],
    services: string[],
    vulnerabilities: number,
}

export interface ScannerStatistics
{
    total_scan: number,
    scan_per_seconds: number,
    available_servers: number,
    total_vulnerabilities: number,
}

export interface SystemStats
{
    cpu_usage: number,
    total_memory_kb: number,
    used_memory_kb: number,
    total_swap_kb: number,
    used_swap_kb: number,
    network_in_bytes: number,
    network_out_bytes: number,
    load_one: number,
    load_five: number,
    load_fiftee: number,
}

export interface SchedulerStats
{
    tasks_per_second: number,
    jobs_per_second: number,
    pending_tasks: number,
}

export interface WorkerStats
{
    system: SystemStats,
    scanner: SchedulerStats,
    analyser: SchedulerStats
}

export interface WorkerConfig
{
    master_addr: string,
    scanner: {
        http: {
            enabled: boolean,
            use_proxy: boolean,
            socks5: boolean,
            timeout: number
        },
        https: {
            enabled: boolean,
            use_proxy: boolean,
            socks5: boolean,
            timeout: number
        },
        ftp: {
            enabled: boolean,
            use_proxy: boolean,
            timeout: number
        },
        ssh: {
            enabled: boolean,
            use_proxy: boolean,
            timeout: number
        },
        scheduler: {
            enabled: boolean,
            max_tasks: number,
            fetch_count: number,
            fetch_threshold: number
        },
    },
    analyser: {
        scheduler: {
            enabled: boolean,
            max_tasks: number,
            fetch_count: number,
            fetch_threshold: number
        },
    }

}

export interface GeoStats
{
    count: number,
    geo: {
        citycode: number,
        city: string,
        province: string,
        region: string,
        country: string,
        isp: string,
        location: {
            type: "Point",
            coordinates: [number, number],
        }
    }
}

const QueryParams = DeclareQuery({
    skip: "number",
    count: "number",
    online_only: {
        type: "number",
        validator: (_, v) => v,
        optional: true,
    },
});

const SkipCountParams = DeclareQuery({
    skip: "number",
    count: "number",
});



export const API = {
    scan: {
        getStats: api("GET", "/api/scan/stats")
            .response<ScannerStatistics>(),
        getByIp: api("GET", "/api/scan/{ip}")
            .path({ ip: IPV4Field })
            .response<ScanResult[]>(),
        getByIpRange: api("GET", "/api/scan/{ip}/{cidr}")
            .path({ ip: IPV4Field, cidr: "number" })
            .query(QueryParams)
            .response<BreifResult[]>(),
        getByIpRangeUrl: api("GET", "/api/scan/{ip}/{cidr}")
            .path({ ip: IPV4Field, cidr: "number" })
            .query(QueryParams)
            .urlBuilder(),
        requestScanIp: api("POST", "/api/scan/{ip}")
            .path({ ip: IPV4Field })
            .response(),
        requestScanIpRange: api("POST", "/api/scan/{ip}/{cidr}")
            .path({ ip: IPV4Field, cidr: "number" })
            .response(),
        requestScanIpList: api("POST", "/api/scan/list")
            .body({
                fetch_urls: {
                    type: "string[]",
                    optional: true,
                    validator: Validator.bypass,
                },
                addr_ranges: {
                    type: "string[]",
                    optional: true,
                    validator: Validator.bypass
                }
            })
            .response<{ tasks: number }>(),
        getPendingTask: api("GET", "/api/scan/task")
            .query(SkipCountParams)
            .response<string[]>(),
        removePendingTask: api("DELETE", "/api/scan/task/{ip}")
            .path({ ip: "string" })
            .response<{ removed_tasks: number }>(),
        clearPendingTask: api("DELETE", "api/scan/task/all")
            .response<{ removed_tasks: number }>(),
    },
    search: {
        listAll: api("GET", "/api/search/all")
            .query(QueryParams)
            .response<BreifResult[]>(),
        searchService: api("GET", "/api/search/service/{service}")
            .path({ service: "string" })
            .query(QueryParams)
            .response<BreifResult[]>(),
        searchServiceUrl: api("GET", "/api/search/service/{service}")
            .path({ service: "string" })
            .query(QueryParams)
            .urlBuilder(),
        searchServiceVersion: api("GET", "/api/search/service/{service}/{version}")
            .path({ service: "string", version: "string" })
            .query(QueryParams)
            .response<BreifResult[]>(),
        searchServiceVersionUrl: api("GET", "/api/search/service/{service}/{version}")
            .path({ service: "string", version: "string" })
            .query(QueryParams)
            .urlBuilder(),
        searchPort: api("GET", "/api/search/port/{port}")
            .path({ port: "number" })
            .query(QueryParams)
            .response<BreifResult[]>(),
        searchPortUrl: api("GET", "/api/search/port/{port}")
            .path({ port: "number" })
            .query(QueryParams)
            .urlBuilder(),
        
    },
    geoStats: {
        all: api("GET", "/api/search/geo_stats/all")
            .response<GeoStats[]>(),
        byIpRange: api("GET", "/api/search/geo_stats/{ip}/{cidr}")
            .path({ ip: IPV4Field, cidr: "number" })
            .response<GeoStats[]>(),
        byServiceName: api("GET", "/api/serach/geo_stats/service/{service}")
            .path({ service: "string" })
            .response<GeoStats[]>(),
        byServiceVersion: api("GET", "/api/search/geo_stats/service/{service}/{version}")
            .path({ service: "string", version: "string" })
            .response<GeoStats[]>(),
        byPort: api("GET", "/api/search/geo_stats/port/{port}")
            .path({ port: "number" })
            .response<GeoStats[]>(),
    },
    stats: {
        getWorkerStats: api("GET", "/api/stats/{worker}/all")
            .path({ worker: "string" })
            .response<WorkerStats>(),
        getMasterSchedulerStats: api("GET", "/api/stats/master")
            .response<{
                tasks_per_second: number,
                jobs_per_second: number,
                pending_tasks: number,
            }>(),
    },
    scheduler: {
        getWorkers: api("GET", "/api/scheduler/workers")
            .response<string[]>(),
        setupWorkerConfig: api("POST", "/api/scheduler/{worker}/setup")
            .path({ worker: "string" })
            .body<WorkerConfig>()
            .response(),
        getWorkerConfig: api("GET", "/api/scheduler/{worker}/status")
            .path({ worker: "string" })
            .response<WorkerConfig | null>()
    },
    analyser: {
        requestFullAnalyse: api("POST", "/api/analyse/all")
            .response<{tasks: number}>(),

    }
};