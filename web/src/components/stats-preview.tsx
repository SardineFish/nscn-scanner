import { Statistic } from "antd";
import React, { CSSProperties, useEffect, useState } from "react";
import { API } from "../api/api";
import InfiniteScroll, { } from "react-infinite-scroller";

export const StatsPreview: React.FC = () =>
{
    const [totalScan, setTotalScan] = useState(0);
    const [allAvailable, setAllAvailable] = useState(0);
    const [vulns, setVulns] = useState(0);
    const [speed, setSpeed] = useState(0);

    useEffect(() =>
    {
        (async () =>
        {
            const stats = await API.scan.getStats({});
            setTotalScan(stats.total_scan);
            setAllAvailable(stats.available_servers);
            setVulns(stats.total_vulnerabilities);
            setSpeed(stats.scan_per_seconds);
        })();
    }, []);

    return (<section className="scan-stats">

        <Statistic title="Total Scanned" suffix="Ips" value={totalScan} valueStyle={ValueStyle}></Statistic>
        <Statistic title="Available" suffix="Ips" value={allAvailable} valueStyle={ValueStyle}></Statistic>
        <Statistic title="Total Vulnerabilities Found" value={vulns} valueStyle={ValueStyle}></Statistic>
        <Statistic title="Scan Speed" suffix="/s" value={speed} valueStyle={ValueStyle} precision={2}></Statistic>
    </section>)
}

const ValueStyle: CSSProperties = {
    fontSize: "4em",
}