import { Button, Checkbox, List, message, Spin, Tag } from "antd";
import Search from "antd/lib/input/Search";
import React, { useEffect, useState } from "react";
import { API, BreifResult } from "../api/api";
import { DatabaseOutlined, ExclamationCircleOutlined } from "@ant-design/icons";
import InfiniteScroll from "react-infinite-scroller";
import { CheckboxChangeEvent } from "antd/lib/checkbox";
import { ScanResultDetail } from "./result-detail";

type LoadFunc = (skip: number, onlineOnly?: boolean) => Promise<BreifResult[]>;

export const ResultSearch: React.FC = () =>
{
    const [data, setData] = useState([] as BreifResult[]);
    const [searchFn, setSearch] = useState(() => search("0.0.0.0/0", 10)[1]);
    const [skip, setSkip] = useState(0);
    const [loading, setLoading] = useState(false);
    const [hasMore, setHasMore] = useState(true);
    const [onlineOnly, setOnlineOnly] = useState(true);
    const [showDetail, setShowDetail] = useState("");

    const onSearch = async (value: string) =>
    {
        try
        {
            const [hasMore, loadFunc] = search(value, 10);
            setSearch(() => loadFunc);
            setHasMore(hasMore);
            setSkip(0);
            setData([]);
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
            const list = await load(skip, onlineOnly);
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


    return (
        <section className="result-search">
            <Search
                className="search-input"
                placeholder="123.123.123.123 or 123.123.123.0/24"
                allowClear
                enterButton size="large"
                onSearch={onSearch} />
            <Checkbox className="search-online-only" checked={onlineOnly} onChange={onlineOnlyChange}>Online Only</Checkbox>
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
    return (<List.Item>
        <List.Item.Meta
            avatar={<DatabaseOutlined style={{ fontSize: "32px" }} />}
            title={<span>
                <span className="addr" onClick={() => props.onClick(props.result.addr)}>{props.result.addr}</span>
                <span className="update-time">{time}</span>
            </span>}
            description={<>
                {
                    props.result.opened_ports.length <= 0
                        ? <Tag color="default">offline</Tag>
                        : props.result.opened_ports.map((port, key) => (<Tag color="green" key={key}>{port}</Tag>))
                }
                {
                    props.result.services.map((service, key) => (<Tag color="blue" key={key}>{service}</Tag>))
                }
                {
                    props.result.vulnerabilities > 0
                        ? <Tag color="warning" icon={<ExclamationCircleOutlined />}>{`vulnerabilities ${props.result.vulnerabilities}`}</Tag>
                        : null
                }
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
function search(input: string, count: number): [boolean, LoadFunc]
{
    if (patterns.empty.test(input))
        return search("0.0.0.0/0", count);
    let matches = patterns.ip.exec(input);
    if (matches)
    {
        const ip = matches[1];
        let cidr = parseInt(matches[2]);
        if (!isNaN(cidr))
        {
            return [true, (skip: number, onlineOnly = false) => API.scan.getByIpRange({ ip: ip, cidr: cidr, skip, count, online_only: onlineOnly? 1: 0})];
        }
        else
            return [false, (_: number, onlineOnly = false) => API.scan.getByIpRange({ ip: ip, cidr: 32, skip: 0, count, online_only: onlineOnly ? 1 : 0})];
    }
    else if (patterns.port.test(input))
    {
        const port = parseInt(input);
        return [true, (skip: number, onlineOnly = false) => API.search.searchPort({ port: port, skip: skip, count, online_only: onlineOnly ? 1 : 0})];
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
                    return search("80", count);
                case "https":
                    return search("443", count);
                case "ftp":
                    return search("21", count);
                case "ssh":
                    return search("22", count);
            }
            return [true, (skip: number, onlineOnly = false) => API.search.searchService({ service, skip: skip, count, online_only: onlineOnly ? 1 : 0 })];
        }
        else
            return [true, (skip: number, onlineOnly = false) => API.search.searchServiceVersion({ service, version, skip, count, online_only: onlineOnly ? 1 : 0 })];
    }
    throw new Error(`Invalid search pattern`);
}