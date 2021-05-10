import { Card, Col, Descriptions, Row, Space, Statistic } from "antd";
import React, { useEffect, useState } from "react";
import { API, SystemStats, WorkerStats } from "../api/api";
// import { Gauge, RingProgress } from "@ant-design/charts";
import RingProgress from "@ant-design/charts/es/ringProgress"
import { formatbytes } from "../utils/utils";
import Text from "antd/lib/typography/Text";
import Title from "antd/lib/typography/Title";
import { ArrowDownOutlined, ArrowUpOutlined } from "@ant-design/icons";

export function WorkerStats(props: {worker: string})
{
    const [stats, setStats] = useState<WorkerStats>({
        system: {
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
        },
        analyser: {
            jobs_per_second: 0,
            pending_tasks: 0,
            tasks_per_second: 0,
        },
        scanner: {
            jobs_per_second: 0,
            pending_tasks: 0,
            tasks_per_second: 0,
        },
    });

    useEffect(() =>
    {
        const interval = setInterval(async () =>
        {
            const stats = await API.stats.getWorkerStats({ worker: props.worker });
            setStats(stats);
        }, 3000);
        return () => clearInterval(interval);
    }, []);

    const usedRAM = `${formatbytes(stats.system.used_memory_kb * 1024, 1)} / ${formatbytes(stats.system.total_memory_kb * 1024, 1)}`;
    const usedSwap = `${formatbytes(stats.system.used_swap_kb * 1024, 1)} / ${formatbytes(stats.system.total_swap_kb * 1024, 1)}`;
    const memUsage = stats.system.used_memory_kb / stats.system.total_memory_kb;


    return (<Card title={props.worker} className="worker-stats">
        <Row gutter={24} wrap={false}>
            <Col flex="120px">
                <RingProgress
                    percent={stats.system.cpu_usage / 100}
                    width={120}
                    height={120}
                    autoFit
                    innerRadius={0.9}
                    color={stats.system.cpu_usage < 50 ? "#73d13d" : (stats.system.cpu_usage < 75 ? "#fadb14" : "#ff7a45")}
                    statistic={{
                        content: {
                            formatter: () => "CPU"
                        },
                        title: {
                            formatter: () => stats.system.cpu_usage
                                .toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + "%"
                        }
                    }}
                    animation={false}
                />
            </Col>
            <Col flex="120px">
                <RingProgress
                    percent={stats.system.used_memory_kb / stats.system.total_memory_kb}
                    width={120}
                    height={120}
                    color={memUsage < 0.5 ? "#73d13d" : (memUsage < 0.75 ? "#fadb14" : "#ff7a45")}
                    statistic={{
                        content: {
                            formatter: () => "Memory"
                        },
                        title: {
                            formatter: () => `${(memUsage * 100)
                                .toLocaleString(undefined, { maximumFractionDigits: 2 })}%`
                        }
                    }}
                    innerRadius={0.9}
                    animation={false}
                />
            </Col>
            <Col flex="auto">
                <Row gutter={[0, 24]}>
                    <Col span={6}>
                        <Statistic title="Used Memory" value={usedRAM} />
                    </Col>
                    <Col span={6}>
                        <Statistic title="Used Swap" value={usedSwap} />
                    </Col>
                    <Col span={6}>
                        <Statistic
                            title="Network Send"
                            value={formatbytes(stats.system.network_out_bytes)}
                            prefix={<ArrowUpOutlined />}
                            valueStyle={{ color: "#f5222d" }}
                            suffix="/s"
                        />
                    </Col>
                    <Col span={6}>
                        <Statistic
                            title="Network Recv"
                            value={formatbytes(stats.system.network_in_bytes)}
                            prefix={<ArrowDownOutlined />}
                            valueStyle={{ color: "#52c41a" }}
                            suffix="/s"
                        />
                    </Col>
                    <Col span={6}>
                        <Statistic title="Pending Scan" value={stats.scanner.pending_tasks} />
                    </Col>
                    <Col span={6}>
                        <Statistic title="Scan Speed" value={stats.scanner.tasks_per_second} suffix="/s" />
                    </Col>
                    <Col span={6}>
                        <Statistic title="Pending Analyser" value={stats.analyser.pending_tasks} />
                    </Col>
                    <Col span={6}>
                        <Statistic title="Analyse Speed" value={stats.analyser.tasks_per_second} suffix="/s" />
                    </Col>
                </Row>
            </Col>
        </Row>
    </Card>)
}
