import { Checkbox, List, message, Spin, Tag } from "antd";
import Search from "antd/lib/input/Search";
import React, { useEffect, useState } from "react";
import { API, BreifResult } from "../api/api";
import { DatabaseOutlined, ExclamationCircleOutlined } from "@ant-design/icons";
import InfiniteScroll from "react-infinite-scroller";
import { CheckboxChangeEvent } from "antd/lib/checkbox";

export const ResultSearch: React.FC = () =>
{
    const [data, setData] = useState([] as BreifResult[]);
    const [searchAddr, setSearch] = useState({ ip: "0.0.0.0", cidr: 0 });
    const [skip, setSkip] = useState(0);
    const [loading, setLoading] = useState(false);
    const [hasMore, setHasMore] = useState(true);
    const [onlineOnly, setOnlineOnly] = useState(false);

    const search = async (value: string) =>
    {
        try
        {
            const reg = /([^/]+)(?:\/(\d+))?/;
            const matches = reg.exec(value);
            if (!matches)
                throw new Error(`Invalid IP Address ${value}`);
            const ip = matches[1];
            let cidr = parseInt(matches[2]);
            
            if (!isNaN(cidr))
            {
                setHasMore(true);
            }
            else
            {
                cidr = 32;
                setHasMore(false);
            }
            setSearch({ ip: ip, cidr: cidr });
            setSkip(0);
            setData([]);
            loadMore({ ip: ip, cidr: cidr }, [], true);
        }
        catch (err)
        {
            message.error(err);
        }
    };

    const loadMore = async (addr: {ip: string, cidr: number}, oldData: BreifResult[] = data, showMessage = false) =>
    {
        try
        {
            setLoading(true);
            const list = await API.scan.getByIpRange({ ...addr, skip, count: 10, online_only: onlineOnly ? 1 : 0 });
            setData([...oldData, ...list]);
            setSkip(skip + list.length);
            setLoading(false);
            if (showMessage)
                message.info(`Show ${list.length} results`);
        }
        catch (err)
        {
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
                onSearch={search} />
            <Checkbox className="search-online-only" checked={onlineOnly} onChange={onlineOnlyChange}>Online Only</Checkbox>
            <InfiniteScroll
                className="scan-results"
                initialLoad={true}
                pageStart={0}
                hasMore={!loading && hasMore}
                loadMore={() => loadMore(searchAddr)}
            >
                <List
                    dataSource={data}
                    itemLayout="vertical"
                    renderItem={item => (<SearchResultItem result={item}/>)} />
                {
                    loading
                        ? <Spin />
                        : null
                }
            </InfiniteScroll>
        </section>
    )
}

const SearchResultItem = (props: {result: BreifResult}) =>
{
    const time = new Date(props.result.last_update).toLocaleString();
    return (<List.Item>
        <List.Item.Meta
            avatar={<DatabaseOutlined style={{ fontSize: "32px" }} />}
            title={<span>{props.result.addr} <span className="update-time">{time}</span></span>}
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