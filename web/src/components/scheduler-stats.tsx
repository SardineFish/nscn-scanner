import { Card, Statistic } from "antd";
import React, { useEffect, useState } from "react";
import { API, SchedulerStats } from "../api/api";

export function SchedulerStatsPanel()
{
    const [stats, setStats] = useState<SchedulerStats>({
        pending_addrs: 0,
        tasks_per_second: 0,
        ip_per_second: 0,
    });
    useEffect(() =>
    {
        setInterval(async () =>
        {
            const stats = await API.stats.getSchedulerStats({});
            setStats(stats);
        }, 3000);
    }, []);
    return (<Card className="scheduler-stats" title="Scheduler Status">
        <Statistic title="Pending IPs" value={stats.pending_addrs} />
        <Statistic title="Scaned IP/s" value={stats.ip_per_second} />
        <Statistic title="Scheduled Tasks/s" value={stats.tasks_per_second}/>
    </Card>)
}