import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import { Badge, Button, Card, Descriptions, Modal, Space, Statistic } from "antd";
import React, { useEffect, useState } from "react";
import { API, SchedulerStats } from "../api/api";
import { ClearAllTasks } from "./clear-all-tasks";
import { NewScanTask } from "./new-scan-task";

export function SchedulerStatsPanel()
{
    const [stats, setStats] = useState<SchedulerStats>({
        pending_addrs: 0,
        tasks_per_second: 0,
        ip_per_second: 0,
    });
    const [showNewTask, setShowNewTask] = useState(false);
    const [showClearConfirm, setClearComfirm] = useState(false);

    useEffect(() =>
    {
        const interval = setInterval(async () =>
        {
            const stats = await API.stats.getSchedulerStats({});
            setStats(stats);
        }, 3000);
        return () => clearInterval(interval);
    }, []);

    return (<Card className="scheduler-stats" title="Scheduler Status">
        <Space direction="vertical" size={30}>
            <Descriptions column={6}>
                <Descriptions.Item label="Status"><Badge status="success" text="Running"></Badge></Descriptions.Item>
                <Descriptions.Item label="Active Scanners">1</Descriptions.Item>
                <Descriptions.Item label="Active Analysers">1</Descriptions.Item>
                <Descriptions.Item label="Tasks Limit">2400</Descriptions.Item>
            </Descriptions>
            <Space direction="horizontal" size={30}>
                <Statistic title="Pending IPs" value={stats.pending_addrs} />
                <Statistic title="Scaned IP/s" value={stats.ip_per_second} />
                <Statistic title="Scheduled Tasks/s" value={stats.tasks_per_second} />
            </Space>
            <Space direction="horizontal" size={30}>
                <NewScanTask/>
                <ClearAllTasks/>
            </Space>
        </Space>
    </Card>)
}