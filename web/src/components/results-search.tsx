import { Button, Checkbox, List, message, Space, Spin, Tag } from "antd";
import Search from "antd/lib/input/Search";
import React, { useEffect, useState } from "react";
import { API, BreifResult, GeoStats } from "../api/api";
import { DatabaseOutlined, DownloadOutlined, ExclamationCircleOutlined } from "@ant-design/icons";
import InfiniteScroll from "react-infinite-scroller";
import { CheckboxChangeEvent } from "antd/lib/checkbox";
import { ScanResultDetail } from "./result-detail";
import { ResultMap } from "./result-map";

type LoadFunc = (skip: number, count: number, onlineOnly?: boolean) => Promise<BreifResult[]>;

export const ResultSearch: React.FC = () =>
{
    const [data, setData] = useState([] as BreifResult[]);
    const [searchFn, setSearch] = useState(() => search("0.0.0.0/0")[1]);
    const [searchValue, setSearchValue] = useState("0.0.0.0/0");
    const [skip, setSkip] = useState(0);
    const [loading, setLoading] = useState(false);
    const [hasMore, setHasMore] = useState(true);
    const [onlineOnly, setOnlineOnly] = useState(true);
    const [showDetail, setShowDetail] = useState("");
    const [geoStats, setGeoStats] = useState<GeoStats[]>([]);

    useEffect(() =>
    {
        (async () =>
        {
            setGeoStats(await searchGeoStats("0.0.0.0/0"));
        })();
    }, []);
    const onSearch = async (value: string) =>
    {
        try
        {
            const [hasMore, loadFunc] = search(value);
            setSearch(() => loadFunc);
            setSearchValue(value);
            setHasMore(hasMore);
            setSkip(0);
            setData([]);
            setGeoStats(await searchGeoStats(value));
            // loadMore({ ip: ip, cidr: cidr }, [], true);
        }
        catch (err)
        {
            message.error(err);
            setHasMore(false);
            setSkip(0);
            setData([]);
        }
    };

    const loadMore = async (load: LoadFunc, oldData: BreifResult[] = data, showMessage = false) =>
    {
        try
        {
            setLoading(true);
            const list = await load(skip, 10, onlineOnly);
            setData([...oldData, ...list]);
            setSkip(skip + list.length);
            setLoading(false);
            if (list.length === 0)
                setHasMore(false);
            if (showMessage)
                message.info(`Show ${list.length} results`);
        }
        catch (err)
        {
            setLoading(false);
            setHasMore(false);
            message.error(err.message);
        }
    };

    const onlineOnlyChange = (e: CheckboxChangeEvent) =>
    {
        setOnlineOnly(e.target.checked);
        if (!loading)
        {
            setSkip(0);
            setData([]);
            // loadMore(searchAddr, [], true);
        }
    }

    const exportResults = async () =>
    {
        const url = searchLoadUrl(searchValue)(0, 0, onlineOnly);
        // const json = JSON.stringify(result);
        // const file = new Blob([json], { type: "application/json" });
        const a = document.createElement("a");
        // a.href = URL.createObjectURL(file);
        a.href = url;
        a.download = `result-${searchValue}.json`;
        a.click();
    };


    return (
        <section className="result-search">
            <ResultMap data={geoStats}/>
            <Search
                className="search-input"
                placeholder="123.123.123.123 or 123.123.123.0/24"
                allowClear
                enterButton size="large"
                onSearch={onSearch} />
            <Space style={{width: "100%", justifyContent:"flex-end"}}>
                <Checkbox className="search-online-only" checked={onlineOnly} onChange={onlineOnlyChange}>Online Only</Checkbox>
                <Button type="link" icon={<DownloadOutlined />} onClick={exportResults}>Export</Button>
            </Space>
            <InfiniteScroll
                className="scan-results"
                initialLoad={true}
                pageStart={0}
                hasMore={!loading && hasMore}
                loadMore={() => loadMore(searchFn)}
            >
                <List
                    dataSource={data}
                    itemLayout="vertical"
                    renderItem={item => (<SearchResultItem result={item} onClick={addr => setShowDetail(addr)} />)} />
                {
                    loading
                        ? <Spin />
                        : null
                }
            </InfiniteScroll>
            <ScanResultDetail addr={showDetail} visible={showDetail !== ""} onClose={() => setShowDetail("")} />
        </section>
    )
}

const SearchResultItem = (props: { result: BreifResult, onClick: (addr: string) => any }) =>
{
    const time = new Date(props.result.last_update).toLocaleString();
    const vulns = props.result.services.reduce((sum, current) => sum + current.vulns, 0);
    return (<List.Item>
        <List.Item.Meta
            avatar={<DatabaseOutlined style={{ fontSize: "32px" }} />}
            title={<span>
                <span className="addr" onClick={() => props.onClick(props.result.addr)}>{props.result.addr}</span>
                <span className="update-time">{time}</span>
            </span>}
            description={<>
                {
                    props.result.ports.length <= 0
                        ? <Tag color="default">offline</Tag>
                        : props.result.ports.map((port, key) => (<Tag color="green" key={key}>{port}</Tag>))
                }
                {
                    props.result.services.map((service, key) => (
                        <Tag color="blue" key={key}>
                            {service.name}
                            {service.version !== "" ? ` ${service.version}` : null}
                        </Tag>))
                }
                {/* {
                    vulns > 0
                        ? <Tag color="warning" icon={<ExclamationCircleOutlined />}>{`vulnerabilities ${vulns}`}</Tag>
                        : null
                } */}
            </>}
        />

    </List.Item>)
}

const patterns = {
    ip: /^(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})(?:\/(\d+))?$/,
    port: /^\d+$/,
    serviceVersion: /^(.+?)(?:\s+(\d+(?:.\d+)*))?$/,
    empty: /^\s+$|^$/
}
function search(input: string): [boolean, LoadFunc]
{
    if (patterns.empty.test(input))
        return search("0.0.0.0/0");
    let matches = patterns.ip.exec(input);
    if (matches)
    {
        const ip = matches[1];
        let cidr = parseInt(matches[2]);
        if (!isNaN(cidr))
        {
            return [true, (skip, count, onlineOnly = false) => API.scan.getByIpRange({ ip: ip, cidr: cidr, skip, count, online_only: onlineOnly? 1: 0})];
        }
        else
            return [false, (_, count, onlineOnly = false) => API.scan.getByIpRange({ ip: ip, cidr: 32, skip: 0, count, online_only: onlineOnly ? 1 : 0})];
    }
    else if (patterns.port.test(input))
    {
        const port = parseInt(input);
        return [true, (skip, count, onlineOnly = false) => API.search.searchPort({ port: port, skip: skip, count, online_only: onlineOnly ? 1 : 0})];
    }
    matches = patterns.serviceVersion.exec(input);
    if (matches)
    {
        const service = matches[1];
        const version = matches[2];
        if (!version)
        {
            switch (service.toLowerCase())
            {
                case "http":
                    return search("80");
                case "https":
                    return search("443");
                case "ftp":
                    return search("21");
                case "ssh":
                    return search("22");
            }
            return [true, (skip, count, onlineOnly = false) => API.search.searchService({ service, skip: skip, count, online_only: onlineOnly ? 1 : 0 })];
        }
        else
            return [true, (skip, count, onlineOnly = false) => API.search.searchServiceVersion({ service, version, skip, count, online_only: onlineOnly ? 1 : 0 })];
    }
    throw new Error(`Invalid search pattern`);
}

function searchLoadUrl(input: string): (skip: number, count: number, onlineOnly?: boolean) => string
{
    if (patterns.empty.test(input))
        return searchLoadUrl("0.0.0.0/0");
    let matches = patterns.ip.exec(input);
    if (matches)
    {
        const ip = matches[1];
        let cidr = parseInt(matches[2]);
        if (!isNaN(cidr))
        {
            return (skip, count, onlineOnly = false) => API.scan.getByIpRangeUrl({ ip: ip, cidr: cidr, skip, count, online_only: onlineOnly ? 1 : 0 });
        }
        else
            return (_, count, onlineOnly = false) => API.scan.getByIpRangeUrl({ ip: ip, cidr: 32, skip: 0, count, online_only: onlineOnly ? 1 : 0 });
    }
    else if (patterns.port.test(input))
    {
        const port = parseInt(input);
        return (skip, count, onlineOnly = false) => API.search.searchPortUrl({ port: port, skip: skip, count, online_only: onlineOnly ? 1 : 0 });
    }
    matches = patterns.serviceVersion.exec(input);
    if (matches)
    {
        const service = matches[1];
        const version = matches[2];
        if (!version)
        {
            switch (service.toLowerCase())
            {
                case "http":
                    return searchLoadUrl("80");
                case "https":
                    return searchLoadUrl("443");
                case "ftp":
                    return searchLoadUrl("21");
                case "ssh":
                    return searchLoadUrl("22");
            }
            return (skip, count, onlineOnly = false) => API.search.searchServiceUrl({ service, skip: skip, count, online_only: onlineOnly ? 1 : 0 });
        }
        else
            return (skip, count, onlineOnly = false) => API.search.searchServiceVersionUrl({ service, version, skip, count, online_only: onlineOnly ? 1 : 0 });
    }
    throw new Error(`Invalid search pattern`);
}

function searchGeoStats(input: string): Promise<GeoStats[]>
{
    if (patterns.empty.test(input))
        return API.geoStats.all({});
    let matches = patterns.ip.exec(input);
    if (matches)
    {
        const ip = matches[1];
        let cidr = parseInt(matches[2]);
        if (!isNaN(cidr))
        {
            return API.geoStats.byIpRange({ ip: ip, cidr });
        }
        else
            return API.geoStats.byIpRange({ ip, cidr: 32 });
    }
    else if (patterns.port.test(input))
    {
        const port = parseInt(input);
        return API.geoStats.byPort({ port });
    }
    matches = patterns.serviceVersion.exec(input);
    if (matches)
    {
        const service = matches[1];
        const version = matches[2];
        if (!version)
        {
            switch (service.toLowerCase())
            {
                case "http":
                    return searchGeoStats("80");
                case "https":
                    return searchGeoStats("443");
                case "ftp":
                    return searchGeoStats("21");
                case "ssh":
                    return searchGeoStats("22");
            }
            return API.geoStats.byServiceName({ service });
        }
        else
            return API.geoStats.byServiceVersion({ service, version });
    }
    throw new Error(`Invalid search pattern`);
}