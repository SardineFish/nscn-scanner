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

interface ScanResult
{
    addr: string,
    opened_ports: number[],
    http_response: null | {
        status: number,
        header: Record<string, string>,
    },
    https_certificate: null | string,
    ftp_access: null | "Anonymous" | "Login",
    ssh_server: null | string,
    services: Record<string, {
        name: string,
        version: string,
        vulnerabilities: Array<{
            id: string,
            title: string,
            url: string,
        }>
    }>
}

interface BreifResult
{
    addr: string,
    opened_ports: number[],
    services: string[],
    vulnerabilities: number,
}

const QueryParams = DeclareQuery({
    skip: "number",
    count: "number"
});

export const API = {
    scan: {
        getByIp: api("GET", "/api/scan/{ip}")
            .path({ ip: IPV4Field })
            .response<ScanResult[]>(),
        getByIpRange: api("GET", "/api/scan/{ip}/{cidr}")
            .path({ ip: IPV4Field, cidr: "number" })
            .query(QueryParams)
            .response<ScanResult[]>(),
        requestScanIp: api("POST", "/api/scan/{ip}")
            .path({ ip: IPV4Field })
            .response(),
        requestScanIpRange: api("POST", "/api/scan/{ip}/{cidr}")
            .path({ ip: IPV4Field, cidr: "number" })
            .response(),
    },
    search: {
        listAll: api("GET", "/api/search/all")
            .query(QueryParams)
            .response<BreifResult[]>(),
        searchService: api("GET", "/api/search/service/{service}")
            .path({ service: "string" })
            .query(QueryParams)
            .response<BreifResult[]>(),
        searchServiceVersion: api("GET", "/api/search/service/{service}/{version}")
            .path({ service: "string", version: "string" })
            .query(QueryParams)
            .response<BreifResult[]>()
    }
};