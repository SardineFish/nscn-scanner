import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import { Badge, Button, Card, Descriptions, message, Modal, Space, Statistic } from "antd";
import React, { useEffect, useState } from "react";
import { API, SchedulerStats } from "../api/api";
import { ConfirmButton } from "./confirm-button";
import { NewScanTask } from "./new-scan-task";

export function SchedulerStatsPanel()
{
    const [stats, setStats] = useState<SchedulerStats>({
        analyser: {
            jobs_per_second: 0,
            pending_tasks: 0,
            tasks_per_second: 0,
        },
        scanner: {
            ip_per_second: 0,
            pending_addrs: 0,
            tasks_per_second: 0,
        }
    });

    useEffect(() =>
    {
        const interval = setInterval(async () =>
        {
            const stats = await API.stats.getSchedulerStats({});
            setStats(stats);
        }, 3000);
        return () => clearInterval(interval);
    }, []);

    const clearTasks = async () =>
    {
        try
        {
            const result = await API.scan.clearPendingTask({});
            message.success(`Removed ${result.removed_tasks} tasks`);
        }
        catch (err)
        {
            message.error(err.message);
        }
    };
    const analyseAll = async () =>
    {
        try
        {
            const result = await API.analyser.requestFullAnalyse({}, {});
            message.success(`Scheduled ${result.tasks} tasks`);
        }
        catch (err)
        {
            message.error(err.message);
        }
    };

    return (<Card className="scheduler-stats" title="Scheduler Status">
        <Space direction="vertical" size={30}>
            <Descriptions column={6}>
                <Descriptions.Item label="Status"><Badge status="success" text="Running"></Badge></Descriptions.Item>
                <Descriptions.Item label="Active Scanners">1</Descriptions.Item>
                <Descriptions.Item label="Active Analysers">1</Descriptions.Item>
                <Descriptions.Item label="Tasks Limit">2400</Descriptions.Item>
            </Descriptions>
            <Space direction="horizontal" size={60}>
                <Statistic title="Pending Scan IP" value={stats.scanner.pending_addrs} />
                <Statistic title="Scaned Speed" value={stats.scanner.ip_per_second} suffix="/s"/>
                <Statistic title="Scheduled Scanning Tasks" value={stats.scanner.tasks_per_second} suffix="/s"/>
                <Statistic title="Pending Analyse IP" value={stats.analyser.pending_tasks} />
                <Statistic title="Analyse Speed" value={stats.analyser.tasks_per_second} suffix="/s" />
                <Statistic title="Scheduled Analysing Tasks" value={stats.analyser.jobs_per_second} suffix="/s"/>
            </Space>
            <Space direction="horizontal" size={30}>
                <NewScanTask/>
                <ConfirmButton
                    onOk={clearTasks}
                    buttonProps={{
                        danger: true,
                        icon: (< DeleteOutlined />),
                        size: "large"
                    }}
                    title="Remove All Pending Tasks"
                    confirmText="All pending tasks will be removed?"
                >Clear All Tasks</ConfirmButton>
                <ConfirmButton
                    onOk={analyseAll}
                    buttonProps={{ size: "large" }}
                    title="Schedule Fully Analyse"
                    confirmText="Schedule a fully analyse of all successful scaning results."
                >Schedule Full Analyse</ConfirmButton>
            </Space>
        </Space>
    </Card>)
}