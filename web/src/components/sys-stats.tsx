import { Descriptions, Statistic } from "antd";
import React, { useEffect, useState } from "react";
import { API, SystemStats } from "../api/api";
import { Gauge, RingProgress } from "@ant-design/charts";
import { formatbytes } from "../utils/utils";
import Text from "antd/lib/typography/Text";
import Title from "antd/lib/typography/Title";

export function SysStats()
{
    const [stats, setStats] = useState<SystemStats>({
        cpu_usage: 0,
        total_memory_kb: 0,
        used_memory_kb: 0,
        total_swap_kb: 0,
        used_swap_kb: 0,
        network_in_bytes: 0,
        network_out_bytes: 0,
        load_one: 0,
        load_five: 0,
        load_fiftee: 0,
    });

    useEffect(() =>
    {
        setInterval(async () =>
        {
            const stats = await API.stats.getSysStats({});
            setStats(stats);
        }, 1000);
        
    }, []);

    const usedRAM = `${formatbytes(stats.used_memory_kb * 1024, 1)} / ${formatbytes(stats.total_memory_kb * 1024, 1)}`;
    const usedSwap = `${formatbytes(stats.used_swap_kb * 1024, 1)} / ${formatbytes(stats.total_swap_kb * 1024, 1)}`;

    return (<section className="sys-stats">
        <RingProgress
            percent={stats.cpu_usage / 100}
            width={160}
            height={160}
            autoFit
            statistic={{
                content: {
                    formatter: () => "CPU"
                },
                title: {
                    formatter: () => stats.cpu_usage.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2}) + "%"
                }
            }}
            animation={false}
        />
        <RingProgress
            percent={stats.used_memory_kb / stats.total_memory_kb}
            width={160}
            height={160}
            statistic={{
                content: {
                    formatter: ()=>"Memory"
                },
                title: {
                    formatter: () => `${(stats.used_memory_kb / stats.total_memory_kb).toLocaleString(undefined, {maximumFractionDigits: 2})}%`
                }
            }}
            animation={false}
        />
        <div className="stats">
            <Title>127.0.0.1</Title>
            <div className="stats-content">
                <Statistic title="Used Memory" value={usedRAM}/>
                <Statistic title="Used Swap" value={usedSwap} />
                <Statistic title="Network Send" value={formatbytes(stats.network_out_bytes)} />
                <Statistic title="Network Recv" value={formatbytes(stats.network_in_bytes)} />
            </div>
        </div>
    </section>)
}
